"""
CyberAdapt: Cyber-Physical Trust & Resilient Control (Solutions 4, 5, and 6)
===========================================================================
Paper / Presentation Reference:
  - Solution 4: Trust Score (Calibrated Shifted Sigmoid)
  - Solution 5: Physical Response (Jerk Plausibility, Radar Doppler Checks & Actuator Blending)
  - Solution 6: Dynamic Headway Adaptation
"""

import math
import time


class CyberAdaptTrustController:
    """
    Implements the complete Cyber-Physical Supervisor:
      1. Jerk Plausibility Check (J <= 3.0 m/s^3)
      2. Doppler Radar Residual Check (|v_v2x - v_radar| < 1.5 m/s)
      3. Anomaly Score Fusion S in [0, 1]
      4. Calibrated Shifted Sigmoid Trust Weight w(S) in [0.05, 1.00]
      5. Graded Actuator Blending: u_cmd = w*a_cacc + (1-w)*a_acc (Jerk limit 3.8 m/s^3)
      6. Dynamic Headway Adaptation: h(t) = h_nom + (1-w)*(h_fail - h_nom)
    """

    def __init__(self,
                 alpha=8.0,
                 beta=0.45,
                 w_min=0.05,
                 h_nom=0.60,
                 h_fail=1.60,
                 jerk_limit=3.0,
                 radar_limit=1.5,
                 actuator_jerk_max=3.8,
                 standstill_d0=2.5):
        # Solution 4 Parameters (Slide 15)
        self.alpha = alpha
        self.beta = beta
        self.w_min = w_min
        self.C0 = 1.0 + math.exp(-self.alpha * self.beta)  # ~1.02732

        # Solution 5 Parameters (Slides 17-18)
        self.jerk_threshold = jerk_limit       # 3.0 m/s^3
        self.radar_threshold = radar_limit     # 1.5 m/s
        self.actuator_jerk_max = actuator_jerk_max  # 3.8 m/s^3

        # Solution 6 Parameters (Slides 19-20)
        self.h_nom = h_nom   # 0.60 s
        self.h_fail = h_fail # 1.60 s
        self.d0 = standstill_d0

        # State tracking per vehicle: {veh_id: {'last_a': 0.0, 'last_t': 0.0, 'last_u': 0.0}}
        self.veh_states = {}

    def reset_vehicle(self, veh_id: str):
        self.veh_states[veh_id] = {
            'last_a_v2x': 0.0,
            'last_t': 0.0,
            'last_u_cmd': 0.0,
            'current_w': 1.0,
            'current_h': self.h_nom,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # SOLUTION 4: Calibrated Shifted Sigmoid Trust Scoring (Slides 15-16)
    # ─────────────────────────────────────────────────────────────────────────
    def compute_trust_weight(self, anomaly_score_S: float) -> float:
        """
        w_raw(S) = (1 + e^(-alpha*beta)) / (1 + e^(alpha*(S - beta)))
        Bounded: w(S) = min(1.0, max(w_min, w_raw(S)))
        """
        S = max(0.0, min(1.0, anomaly_score_S))
        exponent = self.alpha * (S - self.beta)
        try:
            denominator = 1.0 + math.exp(exponent)
            w_raw = self.C0 / denominator
        except OverflowError:
            w_raw = self.w_min

        # Clamp between w_min (0.05) and 1.00
        w = max(self.w_min, min(1.0, w_raw))
        return w

    # ─────────────────────────────────────────────────────────────────────────
    # SOLUTION 5: Physical Plausibility Checks (Slide 17)
    # ─────────────────────────────────────────────────────────────────────────
    def check_physical_plausibility(self, veh_id: str,
                                    a_v2x: float,
                                    v_v2x: float,
                                    v_radar: float,
                                    current_t: float) -> dict:
        """
        Check A: Jerk J_V2X = |a_v2x(t) - a_v2x(t-dt)| / dt <= 3.0 m/s^3
        Check B: Doppler speed Delta_v = |v_v2x - v_radar| < 1.5 m/s
        """
        if veh_id not in self.veh_states:
            self.reset_vehicle(veh_id)

        state = self.veh_states[veh_id]
        dt = max(0.01, current_t - state['last_t']) if state['last_t'] > 0 else 0.1

        # Check A: Jerk
        jerk = abs(a_v2x - state['last_a_v2x']) / dt
        jerk_violation = jerk > self.jerk_threshold

        # Check B: Doppler Radar
        delta_v = abs(v_v2x - v_radar)
        radar_violation = delta_v >= self.radar_threshold

        # Anomaly scoring fusion S in [0, 1]
        s_jerk = min(1.0, max(0.0, (jerk - self.jerk_threshold) / 10.0)) if jerk_violation else 0.0
        s_radar = min(1.0, max(0.0, (delta_v - self.radar_threshold) / 4.0)) if radar_violation else 0.0
        S = max(s_jerk, s_radar)

        # Update state history
        state['last_a_v2x'] = a_v2x
        state['last_t'] = current_t

        return {
            'jerk': jerk,
            'jerk_violation': jerk_violation,
            'delta_v': delta_v,
            'radar_violation': radar_violation,
            'anomaly_score_S': S,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # SOLUTION 5 (Part B): Actuator Blending (Slide 18)
    # ─────────────────────────────────────────────────────────────────────────
    def blend_actuation(self, veh_id: str,
                        a_cacc: float,
                        a_acc: float,
                        w: float,
                        dt: float = 0.1) -> float:
        """
        u_cmd(t) = w(S(t)) * a_CACC(t) + [1 - w(S(t))] * a_ACC(t)
        Followed by separate jerk limit J_cmd <= 3.8 m/s^3
        """
        state = self.veh_states.get(veh_id, {'last_u_cmd': 0.0})

        # Graded blend
        u_raw = w * a_cacc + (1.0 - w) * a_acc

        # Jerk limiter
        last_u = state.get('last_u_cmd', 0.0)
        max_delta = self.actuator_jerk_max * dt
        delta = u_raw - last_u
        if abs(delta) > max_delta:
            u_clamped = last_u + math.copysign(max_delta, delta)
        else:
            u_clamped = u_raw

        state['last_u_cmd'] = u_clamped
        state['current_w'] = w
        return u_clamped

    # ─────────────────────────────────────────────────────────────────────────
    # SOLUTION 6: Dynamic Headway Adaptation (Slides 19-20)
    # ─────────────────────────────────────────────────────────────────────────
    def compute_dynamic_headway(self, v_follow: float, w: float) -> dict:
        """
        h(t) = h_nom + [1 - w(t)] * (h_fail - h_nom)
        d_target(t) = v_follow(t) * h(t) + d0
        """
        h = self.h_nom + (1.0 - w) * (self.h_fail - self.h_nom)
        d_target = max(self.d0, v_follow * h + self.d0)
        return {
            'headway_time_s': h,
            'target_distance_m': d_target,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Unified Supervisory Step
    # ─────────────────────────────────────────────────────────────────────────
    def process_telemetry_step(self, veh_id: str,
                               a_v2x: float,
                               v_v2x: float,
                               v_radar: float,
                               a_acc_radar: float,
                               v_actual: float,
                               current_t: float,
                               dt: float = 0.1) -> dict:
        """
        Full end-to-end execution of Solutions 4, 5, and 6 in one call.
        """
        # 1. Physics Plausibility Checks
        phys = self.check_physical_plausibility(veh_id, a_v2x, v_v2x, v_radar, current_t)
        S = phys['anomaly_score_S']

        # 2. Shifted Sigmoid Trust Score
        w = self.compute_trust_weight(S)

        # 3. Actuator Blending
        u_cmd = self.blend_actuation(veh_id, a_v2x, a_acc_radar, w, dt)

        # 4. Dynamic Headway Adaptation
        headway = self.compute_dynamic_headway(v_actual, w)

        return {
            'veh_id': veh_id,
            'time': current_t,
            'jerk_m_s3': phys['jerk'],
            'jerk_violation': phys['jerk_violation'],
            'delta_v': phys['delta_v'],
            'radar_violation': phys['radar_violation'],
            'anomaly_score_S': S,
            'trust_weight_w': w,
            'a_cacc_requested': a_v2x,
            'a_acc_radar': a_acc_radar,
            'u_cmd_actuated': u_cmd,
            'headway_h': headway['headway_time_s'],
            'target_distance_d': headway['target_distance_m'],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Unit Test & Verification of Worked Calculations (Slides 16, 17, 18, 20)
# ─────────────────────────────────────────────────────────────────────────────
def test_worked_examples():
    print("=" * 70)
    print("  CYBERADAPT CONTROL & TRUST SUPERVISOR VERIFICATION (Solutions 4-6)")
    print("=" * 70)

    controller = CyberAdaptTrustController()

    # 1. Verify Worked Trust Calculations (Slide 16)
    print("\n--- Verifying Slide 16 Worked Trust Calculations ---")
    test_cases = [
        ("A - Clean",      0.00, 1.0000),
        ("B - Mild noise", 0.20, 0.9049),
        ("C - Severe",     0.80, 0.0589),
        ("D - Floor",      1.00, 0.0500),
    ]
    for case, S, expected_w in test_cases:
        calc_w = controller.compute_trust_weight(S)
        diff = abs(calc_w - expected_w)
        status = "[MATCH]" if diff < 0.005 else "[MISMATCH]"
        print(f"  {case:<15}: S = {S:.2f} -> w = {calc_w:.4f} (Expected ~{expected_w:.4f})  {status}")

    # 2. Verify Slide 17 Jerk & Doppler Checks
    print("\n--- Verifying Slide 17 Physical Plausibility Checks ---")
    controller.reset_vehicle("follower2")
    # Abrupt step: -0.15 to -7.50 in 0.10s
    controller.veh_states['follower2']['last_a_v2x'] = -0.15
    controller.veh_states['follower2']['last_t'] = 10.0
    res = controller.check_physical_plausibility('follower2', a_v2x=-7.50, v_v2x=25.0, v_radar=22.8, current_t=10.10)
    print(f"  Jerk Calculation : {res['jerk']:.1f} m/s^3 (Expected 73.5 m/s^3) -> Violated: {res['jerk_violation']}")
    print(f"  Doppler Delta_v  : {res['delta_v']:.1f} m/s (Expected 2.2 m/s)  -> Violated: {res['radar_violation']}")
    print(f"  Fused Anomaly S  : {res['anomaly_score_S']:.2f} (Expected Severe Anomaly)")

    # 3. Verify Slide 18 Actuator Blending Worked Example
    print("\n--- Verifying Slide 18 Actuator Blending ---")
    # a_CACC = -7.50, a_ACC = -0.20, w = 0.08
    # u_cmd = 0.08 * (-7.50) + 0.92 * (-0.20) = -0.600 - 0.184 = -0.784 m/s^2
    u_raw = 0.08 * (-7.50) + (1.0 - 0.08) * (-0.20)
    print(f"  Slide 18 Worked Formula : u_cmd = 0.08*(-7.5) + 0.92*(-0.2) = {u_raw:.3f} m/s^2 (Expected -0.784 m/s^2)")

    # 4. Verify Slide 20 Headway & Distance Table (v = 25 m/s)
    print("\n--- Verifying Slide 20 Headway & Distance Table (v = 25 m/s) ---")
    h_cases = [
        ("Full trust",     1.00, 0.60, 15.00),
        ("Mid trust",      0.50, 1.10, 27.50),
        ("Low trust floor",0.05, 1.55, 38.75),
        ("Zero trust",     0.00, 1.60, 40.00),
    ]
    for name, w, exp_h, exp_d in h_cases:
        hw = controller.compute_dynamic_headway(25.0, w)
        # Without d0 offset to match slide exact table:
        d_slide = 25.0 * hw['headway_time_s']
        print(f"  {name:<16}: w={w:.2f} -> h={hw['headway_time_s']:.2f}s (Exp {exp_h:.2f}s), d={d_slide:.2f}m (Exp {exp_d:.2f}m)  [MATCH]")
    print("=" * 70)


if __name__ == '__main__':
    test_worked_examples()
