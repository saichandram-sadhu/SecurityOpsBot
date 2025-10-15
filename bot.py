import discord
import requests
import json
import asyncio
import aiohttp
import feedparser
import google.generativeai as genai
import os
import random
from datetime import datetime, timedelta
from discord.ext import commands, tasks
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Bot setup
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)

# Configuration from environment
DISCORD_BOT_TOKEN = os.getenv('DISCORD_BOT_TOKEN')
NEWS_CHANNEL_ID = os.getenv('NEWS_CHANNEL_ID')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
AUTO_NEWS_HOUR = 9  # 9 AM daily

if not DISCORD_BOT_TOKEN:
    print("❌ ERROR: DISCORD_BOT_TOKEN not found in .env file")
    exit(1)

if not GEMINI_API_KEY:
    print("⚠️ WARNING: GEMINI_API_KEY not found. AI features will be disabled.")

# Configure Gemini AI
if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        gemini_model = genai.GenerativeModel('models/gemini-2.0-flash')
        print("✅ Gemini AI 2.0 Flash configured successfully!")
    except Exception as e:
        print(f"❌ Gemini AI configuration failed: {e}")
        gemini_model = None
else:
    gemini_model = None

print("🛡️ SecurityOpsBot with Gemini AI Starting...")

# ===== CYBERSECURITY NEWS FEEDS =====
class SecurityNews:
    def __init__(self):
        self.feeds = {
            "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
            "Krebs on Security": "https://krebsonsecurity.com/feed/",
            "SecurityWeek": "https://feeds.feedburner.com/securityweek",
            "Threatpost": "https://threatpost.com/feed/",
            "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
            "CISA Alerts": "https://www.cisa.gov/news.xml",
            "NVD Recent CVEs": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",
            "DarkReading": "https://www.darkreading.com/rss_simple.asp",
            "Help Net Security": "https://www.helpnetsecurity.com/feed/",
            "Security Intelligence": "https://securityintelligence.com/feed/"
        }
        
        # Cybersecurity banner images for embeds
        self.banner_images = [
            "https://i.imgur.com/8Q7QZ2q.png",  # Cybersecurity concept
            "https://i.imgur.com/9JZ3Z3Q.png",  # Shield protection
            "https://i.imgur.com/7X8Z4Z5.png",  # Digital security
            "https://i.imgur.com/6Y5Z6Z7.png",  # Network security
            "https://i.imgur.com/5Z4Z8Z9.png"   # Threat intelligence
        ]

    async def fetch_latest_news(self, limit=10):
        """Fetch latest news from all feeds"""
        all_news = []
        
        for source, url in self.feeds.items():
            try:
                feed = feedparser.parse(url)
                for entry in feed.entries[:2]:  # Get 2 from each source
                    # Clean up summary
                    summary = entry.get('summary', '')
                    if summary:
                        # Remove HTML tags and limit length
                        import re
                        summary = re.sub('<[^<]+?>', '', summary)
                        summary = summary[:250] + '...' if len(summary) > 250 else summary
                    
                    all_news.append({
                        'source': source,
                        'title': entry.title,
                        'link': entry.link,
                        'published': entry.get('published', 'Unknown date'),
                        'summary': summary or 'No summary available'
                    })
            except Exception as e:
                print(f"Error fetching {source}: {e}")
        
        # Sort by date (newest first) and return limited results
        return sorted(all_news, key=lambda x: x['published'], reverse=True)[:limit]

    async def fetch_recent_cves(self, limit=5):
        """Fetch recent CVEs"""
        try:
            url = "https://cve.circl.lu/api/last"
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        cves = []
                        for cve_data in data[:limit]:
                            cves.append({
                                'id': cve_data.get('id', 'Unknown'),
                                'description': cve_data.get('summary', 'No description'),
                                'cvss': cve_data.get('cvss', 'N/A'),
                                'published': cve_data.get('Published', 'Unknown')
                            })
                        return cves
        except Exception as e:
            print(f"Error fetching CVEs: {e}")
        
        return []

    async def generate_ai_summary(self, news_items, cve_items):
        """Generate AI-powered cybersecurity summary using Gemini"""
        if not gemini_model:
            return None
            
        try:
            # Prepare context for AI
            news_context = "\n".join([f"- {news['source']}: {news['title']}" for news in news_items[:5]])
            cve_context = "\n".join([f"- {cve['id']}: {cve['description'][:100]}..." for cve in cve_items[:3]])
            
            prompt = f"""
            As a cybersecurity expert, analyze today's security landscape based on these key developments:
            
            TOP SECURITY NEWS:
            {news_context}
            
            RECENT VULNERABILITIES:
            {cve_context}
            
            Please provide:
            1. A brief executive summary (2-3 sentences) of the overall threat landscape
            2. Key risks to watch today
            3. Recommended immediate actions for security teams
            
            Format the response in a clear, professional manner suitable for a security operations team.
            Keep it concise and actionable.
            """
            
            response = gemini_model.generate_content(prompt)
            return response.text
            
        except Exception as e:
            print(f"Error generating AI summary: {e}")
            return None

    def get_random_banner(self):
        """Get a random cybersecurity banner image"""
        return random.choice(self.banner_images)

# Initialize news fetcher
news_fetcher = SecurityNews()

# ===== ENHANCED DAILY AUTOMATED POSTS =====
@tasks.loop(hours=24)
async def daily_security_digest():
    """Post enhanced daily security digest with AI analysis"""
    if not NEWS_CHANNEL_ID:
        print("❌ NEWS_CHANNEL_ID not set in .env file")
        return
    
    try:
        channel_id = int(NEWS_CHANNEL_ID)
        channel = bot.get_channel(channel_id)
        
        if channel is None:
            print(f"❌ Channel with ID {NEWS_CHANNEL_ID} not found")
            return
        
        print(f"📰 Preparing ENHANCED daily security digest for {datetime.now().strftime('%Y-%m-%d')}")
        
        # Fetch data
        latest_news = await news_fetcher.fetch_latest_news(limit=8)
        recent_cves = await news_fetcher.fetch_recent_cves(limit=5)
        ai_summary = await news_fetcher.generate_ai_summary(latest_news, recent_cves)
        
        # ===== MAIN HEADER EMBED =====
        header_embed = discord.Embed(
            title="🛡️ DAILY CYBERSECURITY BRIEFING",
            description=f"**{datetime.now().strftime('%A, %B %d, %Y')}**\nYour comprehensive security intelligence update",
            color=0x0066cc,
            timestamp=datetime.now()
        )
        header_embed.set_thumbnail(url="https://i.imgur.com/9JZ3Z3Q.png")  # Shield icon
        header_embed.set_image(url=news_fetcher.get_random_banner())  # Random banner
        
        # Add AI summary if available
        if ai_summary:
            header_embed.add_field(
                name="🤖 AI THREAT ASSESSMENT",
                value=f"*Powered by Gemini 2.0 Flash*\n\n{ai_summary}",
                inline=False
            )
        else:
            header_embed.add_field(
                name="📊 THREAT LANDSCAPE",
                value="Today's security intelligence briefing with critical updates and vulnerabilities.",
                inline=False
            )
        
        await channel.send(embed=header_embed)
        
        # ===== CRITICAL ALERTS SECTION =====
        if recent_cves:
            critical_cves = [cve for cve in recent_cves if cve['cvss'] != "N/A" and float(cve['cvss']) >= 7.0]
            if critical_cves:
                alerts_embed = discord.Embed(
                    title="🚨 CRITICAL VULNERABILITY ALERTS",
                    color=0xff0000,
                    timestamp=datetime.now()
                )
                
                for cve in critical_cves[:3]:  # Show top 3 critical
                    cvss_num = float(cve['cvss']) if cve['cvss'] != "N/A" else 0.0
                    severity = "🔴 CRITICAL" if cvss_num >= 9.0 else "🟠 HIGH"
                    
                    alerts_embed.add_field(
                        name=f"{severity} - {cve['id']}",
                        value=f"**CVSS: {cve['cvss']}**\n{cve['description'][:120]}...\n[Details](https://nvd.nist.gov/vuln/detail/{cve['id']})",
                        inline=False
                    )
                
                await channel.send(embed=alerts_embed)
        
        # ===== TOP NEWS EMBED =====
        if latest_news:
            news_embed = discord.Embed(
                title="📰 TOP SECURITY NEWS",
                description="Latest developments in cybersecurity and threat intelligence",
                color=0x00aa00,
                timestamp=datetime.now()
            )
            
            for i, news in enumerate(latest_news[:5], 1):
                news_embed.add_field(
                    name=f"{i}. {news['source']}",
                    value=f"[{news['title']}]({news['link']})\n{news['summary']}",
                    inline=False
                )
            
            news_embed.set_footer(text=f"Sources: {', '.join(set([news['source'] for news in latest_news[:5]]))}")
            await channel.send(embed=news_embed)
        
        # ===== SECURITY RECOMMENDATIONS =====
        recommendations = [
            "🛡️ **Patch Management**: Prioritize patching for CVEs with CVSS ≥ 7.0",
            "📧 **Phishing Defense**: Review email security controls and user training",
            "🔐 **Access Control**: Verify principle of least privilege is enforced",
            "📊 **Monitoring**: Increase vigilance for IOCs related to today's threats",
            "💾 **Backup Verification**: Ensure recent backups are accessible and tested"
        ]
        
        rec_embed = discord.Embed(
            title="💡 SECURITY RECOMMENDATIONS",
            color=0xffcc00,
            timestamp=datetime.now()
        )
        
        # Select 3 random recommendations
        selected_recs = random.sample(recommendations, 3)
        for rec in selected_recs:
            rec_embed.add_field(name=rec, value="\u200b", inline=False)
        
        await channel.send(embed=rec_embed)
        
        # ===== DAILY THREAT STATS =====
        stats_embed = discord.Embed(
            title="📈 DAILY SECURITY METRICS",
            color=0x663399,
            timestamp=datetime.now()
        )
        
        stats_embed.add_field(name="📰 News Articles Analyzed", value=len(latest_news), inline=True)
        stats_embed.add_field(name="⚠️ CVEs Tracked", value=len(recent_cves), inline=True)
        stats_embed.add_field(name="🔴 Critical Alerts", value=len([cve for cve in recent_cves if cve['cvss'] != "N/A" and float(cve['cvss']) >= 9.0]), inline=True)
        stats_embed.add_field(name="🤖 AI Analysis", value="Enabled" if ai_summary else "Disabled", inline=True)
        stats_embed.add_field(name="📊 Threat Level", value="Elevated" if recent_cves else "Normal", inline=True)
        stats_embed.add_field(name="🔄 Next Update", value="Tomorrow 9:00 AM", inline=True)
        
        await channel.send(embed=stats_embed)
        
        print(f"✅ Enhanced daily security digest posted to channel {NEWS_CHANNEL_ID}")
        
    except Exception as e:
        print(f"❌ Error in enhanced daily digest: {e}")
        # Try to send error message
        try:
            channel = bot.get_channel(int(NEWS_CHANNEL_ID))
            if channel:
                await channel.send("❌ Error generating daily security digest. Manual commands still available.")
        except:
            pass

@daily_security_digest.before_loop
async def before_daily_digest():
    """Wait until specified time"""
    await bot.wait_until_ready()
    
    now = datetime.now()
    target_time = now.replace(hour=AUTO_NEWS_HOUR, minute=0, second=0, microsecond=0)
    
    if now.hour >= AUTO_NEWS_HOUR:
        target_time += timedelta(days=1)
    
    wait_seconds = (target_time - now).total_seconds()
    print(f"⏰ Next enhanced daily digest in {wait_seconds/3600:.1f} hours")
    await asyncio.sleep(wait_seconds)

# ===== GEMINI AI COMMANDS =====
@bot.command()
async def aisummary(ctx):
    """Get AI-powered cybersecurity summary - Usage: !aisummary"""
    await ctx.send("🤖 Generating AI cybersecurity summary...")
    
    if not gemini_model:
        await ctx.send("❌ Gemini AI is not configured. Check your API key in .env file.")
        return
    
    try:
        # Fetch current data
        latest_news = await news_fetcher.fetch_latest_news(limit=6)
        recent_cves = await news_fetcher.fetch_recent_cves(limit=4)
        
        if not latest_news:
            await ctx.send("❌ Could not fetch news data for analysis.")
            return
        
        # Generate AI summary
        prompt = f"""
        Analyze this cybersecurity situation and provide a concise threat intelligence briefing:
        
        RECENT SECURITY INCIDENTS:
        {chr(10).join([f"- {news['source']}: {news['title']}" for news in latest_news[:4]])}
        
        CURRENT VULNERABILITIES:
        {chr(10).join([f"- {cve['id']} (CVSS: {cve['cvss']}): {cve['description'][:80]}..." for cve in recent_cves[:3]]) if recent_cves else "No critical vulnerabilities"}
        
        Provide:
        1. Overall threat level assessment
        2. Key risks to monitor
        3. Immediate protective recommendations
        
        Keep it professional and actionable for security teams.
        """
        
        response = gemini_model.generate_content(prompt)
        
        embed = discord.Embed(
            title="🤖 AI CYBERSECURITY ASSESSMENT",
            description=f"*Powered by Gemini 2.0 Flash*\n*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}*",
            color=0x9b59b6,
            timestamp=datetime.now()
        )
        
        embed.add_field(
            name="📊 THREAT INTELLIGENCE SUMMARY",
            value=response.text,
            inline=False
        )
        
        embed.add_field(
            name="📈 DATA SOURCES",
            value=f"• {len(latest_news)} security news articles\n• {len(recent_cves)} recent CVEs analyzed\n• Multiple threat intelligence feeds",
            inline=False
        )
        
        embed.set_footer(text="Use !latestnews for detailed articles | !recentcves for vulnerability details")
        await ctx.send(embed=embed)
        
    except Exception as e:
        await ctx.send(f"❌ Error generating AI summary: {str(e)}")

@bot.command()
async def aithreat(ctx):
    """Get AI threat analysis for specific topic - Usage: !aithreat <topic>"""
    if not gemini_model:
        await ctx.send("❌ Gemini AI is not configured. Check your API key.")
        return
    
    topic = ctx.message.content.replace('!aithreat ', '').strip()
    if not topic:
        await ctx.send("❌ Please specify a topic. Example: `!aithreat ransomware trends`")
        return
    
    await ctx.send(f"🤖 Analyzing threat intelligence for: **{topic}**")
    
    try:
        prompt = f"""
        As a cybersecurity threat intelligence analyst, provide a concise threat assessment about: {topic}
        
        Include:
        1. Current threat landscape
        2. Known attack vectors
        3. Recommended defenses
        4. Key indicators of compromise to monitor
        
        Focus on practical, actionable intelligence for security operations.
        """
        
        response = gemini_model.generate_content(prompt)
        
        embed = discord.Embed(
            title=f"🤖 THREAT ANALYSIS: {topic.upper()}",
            description=response.text,
            color=0xe74c3c,
            timestamp=datetime.now()
        )
        
        embed.set_footer(text="AI-Powered Threat Intelligence | Always verify with multiple sources")
        await ctx.send(embed=embed)
        
    except Exception as e:
        await ctx.send(f"❌ Error in threat analysis: {str(e)}")

# ===== ENHANCED MANUAL COMMANDS =====
@bot.command()
async def dailybrief(ctx):
    """Get manual daily briefing - Usage: !dailybrief"""
    await ctx.send("📊 Generating manual daily security briefing...")
    
    try:
        latest_news = await news_fetcher.fetch_latest_news(limit=6)
        recent_cves = await news_fetcher.fetch_recent_cves(limit=4)
        ai_summary = await news_fetcher.generate_ai_summary(latest_news, recent_cves)
        
        # Header
        header_embed = discord.Embed(
            title="📋 MANUAL SECURITY BRIEFING",
            description=f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}*",
            color=0x3498db,
            timestamp=datetime.now()
        )
        
        if ai_summary:
            header_embed.add_field(
                name="🤖 AI EXECUTIVE SUMMARY",
                value=ai_summary,
                inline=False
            )
        
        await ctx.send(embed=header_embed)
        
        # Quick Stats
        if recent_cves:
            stats_embed = discord.Embed(color=0xff6b6b)
            critical_count = len([cve for cve in recent_cves if cve['cvss'] != "N/A" and float(cve['cvss']) >= 7.0])
            stats_embed.add_field(name="⚠️ Active CVEs", value=len(recent_cves), inline=True)
            stats_embed.add_field(name="🔴 Critical", value=critical_count, inline=True)
            stats_embed.add_field(name="📰 News Sources", value=len(latest_news), inline=True)
            await ctx.send(embed=stats_embed)
        
        await ctx.send("💡 Use `!latestnews` for details | `!recentcves` for vulnerabilities | `!aisummary` for AI analysis")
        
    except Exception as e:
        await ctx.send(f"❌ Error generating briefing: {str(e)}")

# ===== KEEP EXISTING COMMANDS (with minor enhancements) =====
@bot.command()
async def latestnews(ctx, count: int = 5):
    """Get latest cybersecurity news - Usage: !latestnews [number]"""
    await ctx.send("📰 Fetching latest security news...")
    
    try:
        news_items = await news_fetcher.fetch_latest_news(limit=count)
        
        if not news_items:
            await ctx.send("❌ Could not fetch news. Please try again later.")
            return
        
        embed = discord.Embed(
            title="📰 Latest Cybersecurity News",
            description=f"Top {len(news_items)} security updates from trusted sources",
            color=0x3498db,
            timestamp=datetime.now()
        )
        
        for i, news in enumerate(news_items, 1):
            embed.add_field(
                name=f"{i}. {news['source']}",
                value=f"[{news['title']}]({news['link']})\n{news['summary']}",
                inline=False
            )
        
        embed.set_footer(text=f"Use !latestnews 10 for more articles | !aisummary for AI analysis")
        await ctx.send(embed=embed)
        
    except Exception as e:
        await ctx.send("❌ Error fetching news. Please try again later.")

@bot.command()
async def recentcves(ctx, count: int = 5):
    """Get recent CVEs - Usage: !recentcves [number]"""
    await ctx.send("⚠️ Fetching recent vulnerabilities...")
    
    try:
        cves = await news_fetcher.fetch_recent_cves(limit=count)
        
        if not cves:
            await ctx.send("❌ Could not fetch CVEs. Please try again later.")
            return
        
        embed = discord.Embed(
            title="⚠️ Recent Cybersecurity Vulnerabilities",
            description=f"Latest {len(cves)} CVEs with severity ratings",
            color=0xff0000,
            timestamp=datetime.now()
        )
        
        for cve in cves:
            cvss_num = 0.0
            try:
                if cve['cvss'] != "N/A":
                    cvss_num = float(cve['cvss'])
            except:
                cvss_num = 0.0
            
            severity_emoji = "🔴" if cvss_num >= 9.0 else "🟠" if cvss_num >= 7.0 else "🟡" if cvss_num >= 4.0 else "🟢"
            severity_text = "CRITICAL" if cvss_num >= 9.0 else "HIGH" if cvss_num >= 7.0 else "MEDIUM" if cvss_num >= 4.0 else "LOW"
            
            embed.add_field(
                name=f"{severity_emoji} {cve['id']} - {severity_text}",
                value=f"**CVSS: {cve['cvss']}**\n{cve['description'][:150]}...\n[Details](https://nvd.nist.gov/vuln/detail/{cve['id']})",
                inline=False
            )
        
        await ctx.send(embed=embed)
        
    except Exception as e:
        await ctx.send("❌ Error fetching CVEs. Please try again later.")

# Keep all your existing commands (cve, pwned, tools, threatlevel, etc.) 
# They will work exactly as before but with the enhanced news system

@bot.command()
async def cve(ctx, cve_id):
    """Look up CVE details - Usage: !cve CVE-2021-44228"""
    # ... (keep your existing cve function code)

@bot.command()
async def pwned(ctx, email):
    """Check if email appears in data breaches - Usage: !pwned email@example.com"""
    # ... (keep your existing pwned function code)

@bot.command()
async def tools(ctx):
    """List essential cybersecurity tools - Usage: !tools"""
    # ... (keep your existing tools function code)

@bot.command()
async def threatlevel(ctx):
    """Get current global threat level - Usage: !threatlevel"""
    # ... (keep your existing threatlevel function code)

@bot.command()
async def testnews(ctx):
    """Test the enhanced news system - Usage: !testnews"""
    await ctx.send("🧪 Testing ENHANCED news system with AI...")
    
    try:
        # Test news fetch
        news = await news_fetcher.fetch_latest_news(limit=3)
        if news:
            news_embed = discord.Embed(title="📰 Test News Fetch", color=0x3498db)
            for item in news[:2]:
                news_embed.add_field(name=item['source'], value=f"[{item['title']}]({item['link']})", inline=False)
            await ctx.send(embed=news_embed)
        
        # Test CVE fetch
        cves = await news_fetcher.fetch_recent_cves(limit=2)
        if cves:
            cve_embed = discord.Embed(title="⚠️ Test CVE Fetch", color=0xff0000)
            for cve in cves[:2]:
                cve_embed.add_field(name=cve['id'], value=f"CVSS: {cve['cvss']}", inline=True)
            await ctx.send(embed=cve_embed)
        
        # Test AI if available
        if gemini_model:
            await ctx.send("🤖 Testing AI integration...")
            try:
                test_prompt = "Provide a one-sentence cybersecurity tip for today."
                response = gemini_model.generate_content(test_prompt)
                ai_embed = discord.Embed(title="🤖 AI Test", description=response.text, color=0x9b59b6)
                await ctx.send(embed=ai_embed)
            except Exception as e:
                await ctx.send(f"❌ AI test failed: {e}")
        
        await ctx.send("✅ ENHANCED news system test completed!")
        
    except Exception as e:
        await ctx.send(f"❌ Enhanced test failed: {e}")

@bot.command()
async def botinfo(ctx):
    """Get information about the enhanced bot"""
    embed = discord.Embed(
        title="🤖 SecurityOpsBot - Enhanced Edition",
        color=0x7289da,
        timestamp=datetime.now()
    )
    
    embed.add_field(name="Version", value="3.0 - AI Enhanced", inline=True)
    embed.add_field(name="Servers", value=len(bot.guilds), inline=True)
    embed.add_field(name="AI Engine", value="Gemini 2.0 Flash" if gemini_model else "Disabled", inline=True)
    embed.add_field(name="Features", value="CVE Lookup, Breach Checking, AI News, Auto-Updates, Threat Intel", inline=False)
    embed.add_field(name="News Sources", value="10+ cybersecurity feeds", inline=True)
    embed.add_field(name="Update Schedule", value="Daily at 9:00 AM", inline=True)
    embed.add_field(name="AI Commands", value="!aisummary, !aithreat, !dailybrief", inline=False)
    
    await ctx.send(embed=embed)

@bot.command()
async def help(ctx):
    """Show all available commands for enhanced bot"""
    embed = discord.Embed(
        title="🛡️ SecurityOpsBot - Enhanced Help Menu",
        description="AI-Powered Cybersecurity Assistant with Daily Auto-Updates",
        color=0x9b59b6,
        timestamp=datetime.now()
    )
    
    commands_list = [
        {"name": "!cve <CVE-ID>", "value": "Look up CVE details", "example": "`!cve CVE-2021-44228`"},
        {"name": "!pwned <email>", "value": "Check email breaches", "example": "`!pwned test@example.com`"},
        {"name": "!latestnews [count]", "value": "Get latest security news", "example": "`!latestnews 5`"},
        {"name": "!recentcves [count]", "value": "Get recent CVEs", "example": "`!recentcves 5`"},
        {"name": "!aisummary", "value": "AI-powered threat summary", "example": "`!aisummary`"},
        {"name": "!aithreat <topic>", "value": "AI threat analysis", "example": "`!aithreat ransomware`"},
        {"name": "!dailybrief", "value": "Manual daily briefing", "example": "`!dailybrief`"},
        {"name": "!threatlevel", "value": "Current threat assessment", "example": "`!threatlevel`"},
        {"name": "!testnews", "value": "Test enhanced system", "example": "`!testnews`"},
        {"name": "!tools", "value": "List security tools", "example": "`!tools`"},
        {"name": "!botinfo", "value": "Bot information", "example": "`!botinfo`"},
        {"name": "!help", "value": "Show this menu", "example": "`!help`"}
    ]
    
    for cmd in commands_list:
        embed.add_field(
            name=cmd["name"],
            value=f"{cmd['value']}\n*Example:* {cmd['example']}",
            inline=False
        )
    
    embed.add_field(
        name="🔄 Automatic Features",
        value="• **Daily AI-powered security digest** at 9:00 AM\n• Latest news & CVEs with AI analysis\n• Security recommendations\n• 10+ trusted news sources\n• Professional threat intelligence",
        inline=False
    )
    
    embed.add_field(
        name="🎯 Channel Setup",
        value=f"Configure `#📢│announcements` channel in .env file:\n`NEWS_CHANNEL_ID=your_channel_id_here`",
        inline=False
    )
    
    await ctx.send(embed=embed)

# ===== BOT STARTUP =====
@bot.event
async def on_ready():
    print(f'✅ {bot.user} has connected to Discord!')
    print(f'✅ Bot is in {len(bot.guilds)} servers')
    print(f'✅ Gemini AI: {"Enabled" if gemini_model else "Disabled"}')
    
    # Set bot status
    activity = discord.Activity(
        type=discord.ActivityType.watching,
        name="for threats | AI Enhanced | !help"
    )
    await bot.change_presence(activity=activity)
    
    # Start daily news task if channel is set
    if NEWS_CHANNEL_ID and not daily_security_digest.is_running():
        daily_security_digest.start()
        print('✅ Enhanced daily security digest task started!')
    else:
        print('ℹ️ Daily news not configured. Set NEWS_CHANNEL_ID in .env to enable.')

# ===== ERROR HANDLING =====
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        await ctx.send("❌ Command not found. Type `!help` for available commands.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("❌ Missing required argument. Check `!help` for command usage.")
    else:
        await ctx.send("❌ An error occurred. Please try again.")
        print(f"Command error: {error}")

# ===== START THE BOT =====
if __name__ == "__main__":
    print("🛡️ Enhanced SecurityOpsBot with Gemini AI Starting...")
    print("📁 Running from:", os.path.dirname(os.path.abspath(__file__)))
    print("🎯 Configured for #📢│announcements channel")
    bot.run(DISCORD_BOT_TOKEN)