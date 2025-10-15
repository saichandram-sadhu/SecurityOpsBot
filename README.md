<<<<<<< HEAD
# SecurityOpsBot - Enhanced Cybersecurity Discord Bot

![SecurityOpsBot Banner](https://i.imgur.com/9JZ3Z3Q.png)

An AI-powered cybersecurity assistant for Discord with daily automated threat intelligence updates.

## 🛡️ Features

### AI-Powered Threat Intelligence
- **Gemini AI Integration**: Get AI-generated summaries of the latest cybersecurity threats
- **Automated Daily Digests**: Scheduled security briefings with threat analysis
- **On-Demand AI Analysis**: Request AI-powered threat assessments anytime

### Automated Security Updates
- **Real-time News Feed**: Aggregates from 10+ trusted cybersecurity sources
- **CVE Monitoring**: Tracks recent vulnerabilities with severity ratings
- **Daily Security Briefings**: Comprehensive threat intelligence delivered automatically

### Manual Security Tools
- **CVE Lookup**: Detailed information about specific vulnerabilities
- **Breach Detection**: Check if emails appear in known data breaches
- **Threat Intelligence**: Lookup IP addresses, domains, and file hashes
- **Security Tools Directory**: Essential cybersecurity tools recommendations

## 🚀 Setup Instructions

1. **Create a Discord Bot**:
   - Go to https://discord.com/developers/applications
   - Create a new application and bot
   - Copy the bot token

2. **Get a Gemini API Key** (optional but recommended):
   - Visit https://ai.google.dev/
   - Create an API key for Gemini

3. **Configuration**:
   - Copy `.env.example` to `.env`
   - Fill in your Discord bot token and API keys
   - Set your news channel ID for automated updates

4. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

5. **Run the Bot**:
   ```bash
   python bot.py
   ```

## 📋 Commands

### AI-Powered Commands
- `!aisummary` - Get AI-generated cybersecurity threat summary
- `!aithreat <topic>` - Get AI analysis for specific threat topics
- `!dailybrief` - Manual daily security briefing with AI insights

### Security Information
- `!latestnews [count]` - Get latest cybersecurity news (default: 5)
- `!recentcves [count]` - Get recent CVEs with severity ratings (default: 5)
- `!cve <CVE-ID>` - Look up specific CVE details
- `!pwned <email>` - Check if an email appears in data breaches
- `!threatintel <indicator>` - Look up threat intelligence for IPs, domains, or hashes
- `!threatlevel` - Get current global threat assessment

### Security Operations
- `!incidentreport [details]` - Create a security incident report template
- `!tools` - List essential cybersecurity tools
- `!testnews` - Test the news system functionality
- `!botinfo` - Get information about the bot
- `!help` - Show all available commands

## 🔄 Automated Features

The bot automatically posts a comprehensive security digest daily at 9:00 AM including:
- AI-powered threat assessment
- Critical vulnerability alerts
- Top security news from trusted sources
- Actionable security recommendations
- Daily threat metrics

## 📡 Data Sources

- The Hacker News
- Krebs on Security
- SecurityWeek
- Threatpost
- BleepingComputer
- CISA Alerts
- NVD Recent CVEs
- DarkReading
- Help Net Security
- Security Intelligence

## 🛠️ Requirements

- Python 3.8+
- Discord Bot Token
- Gemini API Key (optional)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
=======
# SecurityOpsBot

A Discord bot for security operations and monitoring.

## Features
- Security monitoring
- News alerts
- Automated security operations

## Setup
1. Clone the repository
2. Create `.env` file with your tokens
3. Run `pip install -r requirements.txt`
4. Execute `python bot.py`

## Environment Variables
- `DISCORD_BOT_TOKEN` - Your Discord bot token
- `NEWS_CHANNEL_ID` - Channel ID for news updates
- `GENTRIT_APT_KEY` - Gentrit API key
>>>>>>> b35d328004d1a2c472f76b0149a9f89c542cd0ad
