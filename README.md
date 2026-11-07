# CyberLab AI

The latest release is **v4.11**, developed from the supplied v4.9 baseline.

- [Download the complete v4.11 source ZIP](cyberlab_v4_11.zip)
- [Installation, usage, backup and rollback](cyberlab_v4_11/README.md)
- [Changes](cyberlab_v4_11/CHANGELOG.md)
- [Analysis](cyberlab_v4_11/ANALYSIS.md)
- [Test results and validation limitations](cyberlab_v4_11/TEST_RESULTS.md)

Quick start with Python 3.10+ and Bash:

```bash
cd cyberlab_v4_11
python3 -m unittest discover -s tests -v
bash ./start-cyberlab-v4.sh
```

The dashboard binds to loopback port 8780. Ollama is optional for offline
features. Monitoring and scheduled AI analysis require explicit opt-in.
Recommendations do not execute actions or confirm vulnerabilities.
