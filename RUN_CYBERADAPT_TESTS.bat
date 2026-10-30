@echo off
title CyberAdapt Comparative Verification Suite
cd /d "%~dp0"
echo ==============================================================================
echo Running CyberAdapt vs MA-ABSE-AR Comparative Test Suite
echo ==============================================================================
python compare_frameworks.py
echo.
echo ==============================================================================
echo Running Native Rust Cryptographic Core Engine Test Suite
echo ==============================================================================
cd cyberadapt_rust
cargo test --quiet
cargo run --release --quiet
cd ..
echo.
echo Verification Complete!
pause
