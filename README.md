# Clawdy

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> ⚠️ **Experimental** — This app is still under active development. It has been tested and is working with Clawdbot release `2026.1.21-2`.

**Clawdy** is an iOS voice interface for [Clawdbot](https://github.com/clawdbot/clawdbot). It connects via your gateway with both operator and node roles, enabling natural voice conversations with your AI assistant.

## Features

- **Voice Input** — Speak naturally to your Clawdbot
- **Neural TTS** — High-quality voice responses via Kokoro TTS
- **Device Capabilities** — Camera, location, and notifications exposed as agent tools
- **Session History** — Full conversation sync across devices

## Requirements

- iOS 18.0+
- Clawdbot gateway running and accessible
- VPN connection to your home network (if accessing remotely)

## Setup & Pairing

### 1. Configure Gateway Connection

In Clawdy Settings, enter:
- **Gateway Host**: Your Clawdbot server IP/hostname
- **Gateway Port**: 18789 (default)
- **Gateway Token**: Your gateway authentication token

### 2. Pair the Device

On your Clawdbot server, run these commands to allow Clawdy to connect:

```bash
# List pending/available devices
clawdbot devices list

# Allow the device for chat (operator role)
clawdbot devices allow <device-id>

# Allow the device for node capabilities (node role)  
clawdbot devices allow <device-id>
```

Run the allow command twice — once grants operator role (for chat), once grants node role (for camera/location/notifications).

### 3. Connect

Back in Clawdy, tap "Test Connection" or simply start the app — it will auto-connect.

## Troubleshooting

### "Gateway auth token" error

If you see an authentication error when connecting:

1. Open Clawdy Settings
2. Copy your Gateway Token value
3. Paste it into the **Remote Token** field as well
4. Try connecting again

### Connection drops frequently

- Ensure your VPN connection is stable
- Check that the Clawdbot gateway is running: `clawdbot gateway status`
- Restart the gateway if needed: `clawdbot gateway restart`

### Camera/Location not working

- Ensure you've granted Clawdy the necessary iOS permissions
- Check that the device has node role: `clawdbot devices list`
- Node capabilities only work when the app is in foreground

## Building

Prereqs:

- Xcode (current stable)
- [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`)

Generate the Xcode project from `project.yml` and open it:

```bash
xcodegen generate
open Clawdy.xcodeproj
```

Then in Xcode, select a connected device and run. This app requires a physical iOS device (not Simulator) due to MLX/Metal dependencies in KokoroSwift.

You may need to update `DEVELOPMENT_TEAM` in `project.yml` to your own Apple team ID for signing.

## License

MIT License — see [LICENSE](LICENSE) for details.
