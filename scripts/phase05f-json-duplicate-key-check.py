import json, sys

def find_duplicates(text):
    issues = []
    def hook(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                issues.append(k)
            d[k] = v
        return d
    json.loads(text, object_pairs_hook=hook)
    return issues

def main():
    if len(sys.argv) != 2:
        print("USAGE: phase05f-json-duplicate-key-check.py <file>")
        return 2
    with open(sys.argv[1], encoding="utf-8") as f:
        text = f.read()
    try:
        issues = find_duplicates(text)
    except json.JSONDecodeError as e:
        print(f"JSON_PARSE_ERROR: {e}")
        return 1
    if issues:
        for k in sorted(set(issues)):
            print(f"DUPLICATE_KEY: {k}")
        return 1
    print("NO_DUPLICATE_KEYS")
    return 0

if __name__ == "__main__":
    sys.exit(main())
