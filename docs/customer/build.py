#!/usr/bin/env python3
"""Build the customer-facing federated-login approval PDF. Usage: build.py <output-dir>"""
import os, subprocess, sys
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (Image, KeepTogether, ListFlowable, ListItem, PageBreak, Paragraph,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = sys.argv[1]; os.makedirs(OUT, exist_ok=True)
CUSTOMER = os.environ.get("CUSTOMER", "your organization"); DATE = os.environ.get("DOCDATE", "18 September 2026")

def font(family, style):
    """Return (path, subfont index) for a family/style, resolving .ttc collections through PIL."""
    path = subprocess.run(["fc-match", "-f", "%{file}", f"{family}:style={style}"], capture_output=True, text=True).stdout.strip()
    if not path.lower().endswith((".ttf", ".otf", ".ttc")): return None
    if not path.lower().endswith(".ttc"): return (path, 0)
    from PIL import ImageFont
    for i in range(64):
        try: fam, sty = ImageFont.truetype(path, 10, index=i).getname()
        except Exception: break
        if fam == family and sty == style: return (path, i)
    return None
REG = font("Inter", "Regular") or font("DejaVu Sans", "Book"); BOLD = font("Inter", "Bold") or font("DejaVu Sans", "Bold")
pdfmetrics.registerFont(TTFont("Body", REG[0], subfontIndex=REG[1])); pdfmetrics.registerFont(TTFont("BodyBold", BOLD[0], subfontIndex=BOLD[1]))
pdfmetrics.registerFontFamily("Body", normal="Body", bold="BodyBold", italic="Body", boldItalic="BodyBold")

HEAD, TEXT, MUTED, LINE, CYAN, SURFACE = "#08131e", "#1c2932", "#52616a", "#898b88", "#1686a1", "#eae7de"
S = dict(
    kicker=ParagraphStyle("k", fontName="Body", fontSize=9, textColor=MUTED, spaceAfter=2),
    title=ParagraphStyle("t", fontName="BodyBold", fontSize=20, leading=25, textColor=HEAD, spaceAfter=4),
    lede=ParagraphStyle("l", fontName="Body", fontSize=10, leading=14, textColor=MUTED, spaceAfter=10),
    h1=ParagraphStyle("h1", fontName="BodyBold", fontSize=13, leading=17, textColor=HEAD, spaceBefore=12, spaceAfter=5),
    h2=ParagraphStyle("h2", fontName="BodyBold", fontSize=10.5, leading=14, textColor=HEAD, spaceBefore=8, spaceAfter=3),
    body=ParagraphStyle("b", fontName="Body", fontSize=9.6, leading=13.6, textColor=TEXT, spaceAfter=6, alignment=TA_LEFT),
    cell=ParagraphStyle("c", fontName="Body", fontSize=8.8, leading=12, textColor=TEXT),
    cellb=ParagraphStyle("cb", fontName="BodyBold", fontSize=8.8, leading=12, textColor=HEAD),
    small=ParagraphStyle("s", fontName="Body", fontSize=8, textColor=MUTED),
)
def P(t, s="body"): return Paragraph(t, S[s])
def table(rows, widths, header=True, zebra=True):
    data = [[P(c, "cellb" if (header and i == 0) else "cell") for c in r] for i, r in enumerate(rows)]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    st = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
          ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
          ("LINEBELOW", (0, -1), (-1, -1), 0.8, colors.HexColor(HEAD))]
    if header: st += [("LINEBELOW", (0, 0), (-1, 0), 0.8, colors.HexColor(HEAD)), ("LINEABOVE", (0, 0), (-1, 0), 0.8, colors.HexColor(HEAD))]
    if zebra: st += [("BACKGROUND", (0, i), (-1, i), colors.HexColor(SURFACE)) for i in range(1 if header else 0, len(rows)) if (i - (1 if header else 0)) % 2 == 1]
    t.setStyle(TableStyle(st)); return t
def bullets(items): return ListFlowable([ListItem(P(i), leftIndent=10, value="•") for i in items], bulletType="bullet", start="•", leftIndent=12, bulletFontName="Body", bulletFontSize=9)
def numbers(items): return ListFlowable([ListItem(P(i), leftIndent=10) for i in items], bulletType="1", leftIndent=14, bulletFontName="Body", bulletFontSize=9.4)

WIDTH = A4[0] - 44 * mm
def approval():
    rows = [["Approved by", ""], ["Organization", ""], ["Date", ""], ["Automatic account creation on first sign-in", "yes      /      no"]]
    t = Table([[P(a, "cell"), P(b, "cell")] for a, b in rows], colWidths=[WIDTH * 0.42, WIDTH * 0.58], rowHeights=[11 * mm] * 4)
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 5),
                           ("LINEABOVE", (0, 0), (-1, 0), 0.8, colors.HexColor(HEAD)), ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor(LINE)),
                           ("LINEBELOW", (0, -1), (-1, -1), 0.8, colors.HexColor(HEAD))]))
    return t
def chrome(canvas, doc):
    canvas.saveState(); y = A4[1] - 14 * mm
    mark = os.path.join(OUT, "mark.png")
    if os.path.exists(mark): canvas.drawImage(mark, 22 * mm, y - 1.5 * mm, 5.5 * mm, 5.5 * mm, mask="auto")
    canvas.setFont("BodyBold", 9); canvas.setFillColor(colors.HexColor(HEAD)); canvas.drawString(29.5 * mm, y, "beyond10x")
    canvas.setFont("Body", 9); canvas.setFillColor(colors.HexColor(MUTED)); canvas.drawString(29.5 * mm + pdfmetrics.stringWidth("beyond10x", "BodyBold", 9) + 2 * mm, y, "· Mandate")
    canvas.drawRightString(A4[0] - 22 * mm, y, "Signing in with your existing accounts")
    canvas.setStrokeColor(colors.HexColor(LINE)); canvas.setLineWidth(0.4); canvas.line(22 * mm, y - 3.2 * mm, A4[0] - 22 * mm, y - 3.2 * mm)
    canvas.setFont("Body", 8); canvas.drawString(22 * mm, 12 * mm, f"Prepared for {CUSTOMER} · {DATE}"); canvas.drawRightString(A4[0] - 22 * mm, 12 * mm, f"Page {doc.page}")
    canvas.restoreState()

doc = SimpleDocTemplate(os.path.join(OUT, "federated-login-approval.pdf"), pagesize=A4, leftMargin=22 * mm, rightMargin=22 * mm, topMargin=26 * mm, bottomMargin=22 * mm,
                        title="Mandate — signing in with your existing accounts", author="beyond10x")
story = [
    P("For your approval", "kicker"), P("Signing in to Mandate with your existing accounts", "title"),
    P("What your users will experience, how the sign-in works, what we need from you to set it up, how access is taken away again, and what we will never do with your identity data.", "lede"),
    P("What your users experience", "h1"),
    P("A user signs in to your platform the way they do today. When they reach a Mandate-protected service they are already signed in. There is no second password and no separate account to create. The first time a given user arrives, Mandate creates their account automatically from the proof your identity provider issued; every later visit finds it. Nobody — not you, not us — does anything per user."),
    P("How the sign-in works", "h1"),
    Image(os.path.join(OUT, "sso-flow.png"), width=WIDTH, height=WIDTH * 0.71), Spacer(1, 4),
    numbers([
        "The user signs in to your platform. Your identity provider issues a signed proof of who they are.",
        "The user's browser presents that proof to Mandate. Mandate checks — in this order — that the proof came from the identity provider you registered, that its signature is valid, that it was issued to the registered client, that the one-time values match the request, and that it names your organization through the claim you told us to trust. If any check fails, or the proof could belong to more than one organization, the sign-in is refused. Mandate never guesses.",
        "If this is the user's first visit and you have chosen automatic account creation, Mandate creates the account and the link to your identity provider's subject identifier. Otherwise it finds the existing link.",
        "Mandate establishes a session.",
        "Your application asks Mandate for a token on the user's behalf, using the standard authorization-code flow with PKCE. Mandate issues a short-lived token scoped to exactly one audience — the service it is meant for — and to no more authority than the user holds.",
        "Your application calls the Mandate-protected service with that token.",
        "The service checks the token with Mandate before acting on it. A revoked or expired token is refused at that check.",
    ]),
    P("The token your application receives", "h1"),
    table([["Who it is for", "One audience: the specific Mandate-protected service. A token for one service is refused by every other."],
           ["What it carries", "The user, your organization, the audience, the narrowed scope, and an expiry. It never carries your identity provider's token or anything from it."],
           ["How long it lives", "Minutes, not days. Your application refreshes through the session rather than holding long-lived credentials."],
           ["How a service trusts it", "By checking with Mandate, or by verifying Mandate's signature against Mandate's published keys. Services never talk to your identity provider."]],
          [WIDTH * 0.28, WIDTH * 0.72], header=False),
    P("Setting it up", "h1"),
    table([["#", "Step", "Who"],
           ["1", "Register Mandate as a client in your identity provider and note the client identifier it assigns.", "You"],
           ["2", "Send us the items in the table below.", "You"],
           ["3", "We register a federation connection bound to your organization, with the claim that identifies your tenant and the signing algorithms your provider uses.", "We"],
           ["4", "We register your applications' exact redirect addresses.", "We"],
           ["5", "You confirm automatic account creation on first sign-in, or tell us you will provision users ahead of time.", "You"],
           ["6", "We open a test environment against your identity provider; a user of yours signs in end to end.", "Both"],
           ["7", "Go-live. Everything after this is per-organization configuration, never per-user work.", "Both"]],
          [WIDTH * 0.06, WIDTH * 0.80, WIDTH * 0.14]),
    P("What we need from you", "h2"),
    table([["Item", "Why"],
           ["The issuer URL of your identity provider", "It is the trust anchor; Mandate accepts proofs from nowhere else."],
           ["The client identifier assigned to Mandate", "So a proof issued to another application is refused."],
           ["The address where your provider publishes its signing keys", "So signatures are verified against your current keys; rotating keys on your side needs nothing from us."],
           ["The exact claim that identifies your organization, and its value", "This is the only thing that places a user in your organization."],
           ["The signing algorithms your provider uses", "Mandate accepts a fixed, configured list and refuses everything else."],
           ["The redirect addresses of the applications that will sign in", "Only exact registered addresses are accepted."],
           ["Your choice on automatic account creation", "Recommended; the alternative is provisioning users ahead of time."]],
          [WIDTH * 0.42, WIDTH * 0.58]),
    P("Taking access away", "h1"),
    table([["Situation", "Trigger", "Effect"],
           ["A user leaves your organization", "You disable them in your identity provider.", "Their next Mandate session refresh is refused. Tell us, and we end their sessions at once."],
           ["One session looks compromised", "You or we end that session.", "Every token issued from it is refused on its next check."],
           ["One token is exposed", "We revoke that token.", "The next check by any service reports it inactive."],
           ["You need a security reset for one user", "We advance that user's security generation.", "All of their sessions and tokens become stale immediately."],
           ["You need to cut the whole connection", "We disable the connection.", "Every session that came through it is invalidated; nothing new is accepted."]],
          [WIDTH * 0.30, WIDTH * 0.30, WIDTH * 0.40]), Spacer(1, 6),
    P("Two things hold in every row. Revocation is fail-closed: a token or session that has been revoked is refused on its next check, and no cached earlier answer overrides that. And nothing is deleted: the fact that a session existed and was ended is retained; where a record must be removed for privacy, it is redacted in place and the redaction itself is recorded."),
    P("What we will not do", "h1"),
    bullets(["We do not create or store passwords for your users.",
             "We do not merge two accounts because they share an email address. Email is displayed and used for invitations; it never establishes identity.",
             "We do not pass your identity provider's token on to any service. Services receive a Mandate-issued token scoped to what they need, and nothing of yours.",
             "We do not derive your organization from an email domain, a hostname, or anything a user typed.",
             "We do not delete sign-in history or account records."]),
    KeepTogether([P("Where this stands", "h1"),
    P("The behaviour above is specified and reviewed. The components that implement it are being built in stages. The first stage delivers the sign-in path and token issuance with an internal verification step; signature verification against your provider's published keys goes live once the supporting library is admitted. We will tell you when the test environment in step 6 is ready for your identity provider.")]),
    KeepTogether([P("Approval", "h1"), approval()]),
]
doc.build(story, onFirstPage=chrome, onLaterPages=chrome)
print(os.path.join(OUT, "federated-login-approval.pdf"), "fonts:", REG, BOLD)
