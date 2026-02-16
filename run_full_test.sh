#!/bin/bash

# 1. Kill any old versions running
pkill -f diamond_shield

# 2. Build the Rust Engine (Quietly)
echo "⚙️  Compiling DiamondShield Engine..."
cargo build --release --quiet

# 3. Start the Shield in the background & hide logs to keep screen clean
echo "🛡️  Igniting Shield System..."
./target/release/diamond_shield > shield_logs.txt 2>&1 &
SHIELD_PID=$!

# 4. Wait for the engine to warm up
echo "⏳ Waiting for systems to come online..."
sleep 5

# 5. Launch the Attack Simulation
echo "⚔️  STARTING ATTACK SIMULATION"
echo "--------------------------------"
python attack_simulation.py
echo "--------------------------------"

# 6. Cleanup: Kill the background server
kill $SHIELD_PID
echo "✅ Test Complete. Shield Shutdown."
