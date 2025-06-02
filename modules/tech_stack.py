from Wappalyzer import Wappalyzer, WebPage

def run(domain):
    print(f"\n[TECH STACK] Detecting technologies used by: {domain}")
    
    try:
        url = f"https://{domain}"
        webpage = WebPage.new_from_url(url, timeout=10)
        wappalyzer = Wappalyzer.latest()
        technologies = wappalyzer.analyze(webpage)

        if technologies:
            print(" Technologies Detected:")
            for tech in technologies:
                print(f"  - {tech}")
        else:
            print("  [!] No technologies detected.")
    except Exception as e:
        print(f"  [ERROR] Failed to detect tech stack: {e}")
