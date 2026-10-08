# quick phishing checker for the mail export - L. Garcia, march 2025
# TODO: make this nicer at some point
import os
import re
import sys

scores = {}
verdicts = []

KEYWORDS = [
    "urgent",
    "verify",
    "suspended",
    "password",
    "expires",
    "act now",
    "congratulations",
    "winner",
    "claim",
    "immediately",
    "gift card",
]


def check_mail(folder, flagged=[]) -> None:
    files = os.listdir(folder)

    for file in files:
        if not file.endswith(".eml"):
            continue

        raw = open(folder + "/" + file, encoding="utf-8",
                   errors="ignore").read()
        s = 0

        try:
            from_email = re.search("From: (.*)", raw).group(1)
        except:
            from_email = "?"
        try:
            subj = re.search("Subject: (.*)", raw).group(1)
        except:
            subj = "?"

        low = raw.lower()
        for kw in KEYWORDS:
            if kw in low:
                s = s + 1

        # links that look bad
        urls = re.findall("https?://[^\\s\"'<>]+", raw)
        for url in urls:
            if re.match("https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+", url):
                s = s + 3  # ip address url, very bad
            if "xn--" in url:
                s = s + 3

        # sender says paypal/microsoft/amazon but domain is weird
        if "paypal" in from_email.lower() and "paypal.com" not in from_email.lower():
            s = s + 3
        if "microsoft" in from_email.lower() and "microsoft.com" not in from_email.lower():
            s = s + 3
        if "amazon" in from_email.lower() and "amazon.com" not in from_email.lower():
            s = s + 3
        if "spf=fail" in low or "dmarc=fail" in low:
            s = s + 2
        # reply-to different from from
        try:
            rt = re.search("Reply-To: (.*)", raw).group(1)
            m1 = re.search("@([a-zA-Z0-9.-]+)", from_email).group(1)
            m2 = re.search("@([a-zA-Z0-9.-]+)", rt).group(1)
            if m1 != m2:
                s = s + 2
        except:
            pass

        scores[file] = s
        if s >= 5:
            verdicts.append((file, "PHISHING", s))
            flagged.append(file)
        elif s >= 3:
            verdicts.append((file, "suspicious", s))
        else:
            verdicts.append((file, "ok", s))

    print("checked", len(scores), "mails")

    for v in verdicts:
        print(" ", v[0], "->", v[1], "(score", str(v[2]) + ")")

    out = open("results.txt", "w")
    out.write(str(verdicts))
    out.close()
    print("flagged:", flagged)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        check_mail(sys.argv[1])
    else:
        check_mail()
