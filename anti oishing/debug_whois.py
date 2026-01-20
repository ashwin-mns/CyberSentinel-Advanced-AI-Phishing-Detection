import utils

test_urls = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://github.com"
]

print("--- Debugging Domain Age Extraction ---")
for url in test_urls:
    age = utils.get_domain_age(url)
    print(f"URL: {url} | Extracted Age: {age} days")
    
    if age == 0:
        print("  -> WARNING: Failed to fetch age (or age is 0). This causes false positives.")
