"""Generate SUMO network and route files for the MA-ABSE-AR simulation."""
import subprocess, os, sys

SUMO_DIR = r'D:\Cyberadapt\ma_abse_ar\sumo'

# ── Network: straight 2 km highway ──────────────────────────────────────
nodes_xml = """\
<?xml version="1.0" encoding="UTF-8"?>
<nodes>
  <node id="n0" x="0"    y="0" type="priority"/>
  <node id="n1" x="2000" y="0" type="priority"/>
</nodes>
"""

edges_xml = """\
<?xml version="1.0" encoding="UTF-8"?>
<edges>
  <edge id="e0" from="n0" to="n1" priority="1" numLanes="1" speed="33.33"/>
</edges>
"""

# ── Routes: 1 leader + 6 followers at 14 m/s ────────────────────────────
# Paper: initial speed = 14 m/s, vehicle spacing ~20 m
routes_xml = """\
<?xml version="1.0" encoding="UTF-8"?>
<routes>
  <vType id="platoon" accel="2.5" decel="4.5" sigma="0.0" length="5.0"
         minGap="2.0" maxSpeed="33.33" speedFactor="1.0"
         carFollowModel="IDM"
         tau="1.0" delta="4" stepping="0.25"/>

  <!-- Leader -->
  <vehicle id="leader"   type="platoon" depart="0.0" departPos="200"  departSpeed="14"/>
  <!-- Followers: spaced 20 m apart behind leader -->
  <vehicle id="follower1" type="platoon" depart="0.0" departPos="175" departSpeed="14"/>
  <vehicle id="follower2" type="platoon" depart="0.0" departPos="150" departSpeed="14"/>
  <vehicle id="follower3" type="platoon" depart="0.0" departPos="125" departSpeed="14"/>
  <vehicle id="follower4" type="platoon" depart="0.0" departPos="100" departSpeed="14"/>
  <vehicle id="follower5" type="platoon" depart="0.0" departPos="75"  departSpeed="14"/>
  <vehicle id="follower6" type="platoon" depart="0.0" departPos="50"  departSpeed="14"/>

  <route id="straight" edges="e0"/>
</routes>
"""

with open(os.path.join(SUMO_DIR, 'nodes.xml'), 'w') as f:
    f.write(nodes_xml)
with open(os.path.join(SUMO_DIR, 'edges.xml'), 'w') as f:
    f.write(edges_xml)
with open(os.path.join(SUMO_DIR, 'routes.xml'), 'w') as f:
    f.write(routes_xml)

# Generate network with netconvert
result = subprocess.run([
    'netconvert',
    '--node-files', os.path.join(SUMO_DIR, 'nodes.xml'),
    '--edge-files', os.path.join(SUMO_DIR, 'edges.xml'),
    '--output-file', os.path.join(SUMO_DIR, 'highway.net.xml'),
], capture_output=True, text=True)

if result.returncode == 0:
    print("Network generated: highway.net.xml")
else:
    print("netconvert error:", result.stderr)
    sys.exit(1)

# ── SUMO config ──────────────────────────────────────────────────────────
sumo_cfg = f"""\
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <input>
    <net-file value="highway.net.xml"/>
    <route-files value="routes.xml"/>
  </input>
  <time>
    <begin value="0"/>
    <end value="60"/>
    <step-length value="0.1"/>
  </time>
</configuration>
"""
with open(os.path.join(SUMO_DIR, 'sim.sumocfg'), 'w') as f:
    f.write(sumo_cfg)

print("Config written: sim.sumocfg")
print("All SUMO files ready.")
