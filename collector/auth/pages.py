"""Pages HTML (login Supabase, login legacy SMTP, signup) rendues via render_template_string."""


SUPABASE_LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CERBERE — Sign in</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
    <!-- Google Tag Manager -->
<script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
})(window,document,'script','dataLayer','GTM-MK76ZMD6');</script>
<!-- End Google Tag Manager -->
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        :root {
            --bg: #121110;
            --panel: #171512;
            --panel-2: #1c1915;
            --accent: #da7751;
            --accent-soft: rgba(218, 119, 81, 0.12);
            --accent-line: rgba(218, 119, 81, 0.30);
            --text: #ece6db;
            --muted: #8f8579;
            --faint: #5c554c;
            --error: #d96a6a;
            --line: rgba(236, 230, 219, 0.09);
        }

        body {
            font-family: 'JetBrains Mono', 'Courier New', monospace;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            -webkit-font-smoothing: antialiased;
        }

        .shell {
            display: grid;
            grid-template-columns: minmax(420px, 500px) 1fr;
            min-height: 100vh;
        }

        /* GAUCHE — formulaire */
        .pane-form {
            display: flex;
            flex-direction: column;
            justify-content: center;
            padding: 48px 52px;
            background: var(--panel);
            border-right: 1px solid var(--line);
        }

        .form-inner { width: 100%; max-width: 380px; margin: 0 auto; }

        .brand-mini {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 42px;
        }
        .brand-mini img { width: 26px; height: 26px; border-radius: 5px; }
        .brand-mini span {
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 0.22em;
            color: var(--text);
        }

        .welcome h1 {
            font-size: 22px;
            font-weight: 700;
            margin-bottom: 8px;
        }
        .welcome p {
            font-size: 13px;
            color: var(--muted);
            line-height: 1.6;
            margin-bottom: 30px;
        }

        .prompt-line {
            font-size: 12px;
            color: var(--faint);
            margin-bottom: 18px;
        }
        .prompt-line .sig { color: var(--accent); }

        .field-label {
            display: block;
            font-size: 12px;
            color: var(--muted);
            margin-bottom: 7px;
        }
        .field-label::before { content: '> '; color: #b75f40; }

        input[type="email"], input[type="text"] {
            width: 100%;
            padding: 12px 14px;
            background: var(--bg);
            border: 1px solid var(--line);
            color: var(--text);
            font-family: inherit;
            font-size: 13.5px;
            outline: none;
            border-radius: 6px;
            caret-color: var(--accent);
            transition: border-color .15s ease, box-shadow .15s ease;
        }
        input:focus {
            border-color: var(--accent-line);
            box-shadow: 0 0 0 3px var(--accent-soft);
        }
        input::placeholder { color: var(--faint); }

        .btn {
            width: 100%;
            padding: 12px;
            font-family: inherit;
            font-size: 12.5px;
            font-weight: 700;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            cursor: pointer;
            border-radius: 6px;
            border: 1px solid #da7753;
            background: #b75f40;
            color: #1a120c;
            transition: all .15s ease;
            margin-top: 14px;
        }
        .btn:hover:not(:disabled) { filter: brightness(1.08); }
        .btn:active:not(:disabled) { transform: translateY(1px); }
        .btn:disabled { opacity: 0.5; cursor: default; }

        .rule {
            display: flex;
            align-items: center;
            gap: 14px;
            margin: 22px 0;
            color: var(--faint);
            font-size: 10.5px;
            letter-spacing: 0.22em;
            user-select: none;
        }
        .rule::before, .rule::after {
            content: '';
            flex: 1;
            height: 1px;
            background: var(--line);
        }

        .oauth-row { display: flex; flex-direction: column; gap: 10px; }

        .btn-oauth {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            background: transparent;
            color: var(--text);
            border: 1px solid var(--line);
            margin-top: 0;
        }
        .btn-oauth:hover:not(:disabled) {
            border-color: var(--accent-line);
            background: var(--accent-soft);
            color: var(--text);
            filter: none;
        }
        .btn-oauth svg { width: 15px; height: 15px; flex-shrink: 0; }

        .signup-note {
            margin-top: 26px;
            padding-top: 20px;
            border-top: 1px solid var(--line);
            font-size: 11.5px;
            color: var(--faint);
            line-height: 1.7;
        }
        .signup-note strong { color: var(--muted); }

        .signup-link {
            margin-top: 20px;
            font-size: 12px;
            color: var(--muted);
        }
        .signup-link a { color: var(--accent); text-decoration: none; }
        .signup-link a:hover { text-decoration: underline; }

        .alert {
            padding: 11px 14px;
            font-size: 12.5px;
            line-height: 1.6;
            margin-bottom: 18px;
            border-radius: 6px;
            font-family: inherit;
        }
        .alert-error {
            border: 1px solid rgba(217, 106, 106, 0.4);
            background: rgba(217, 106, 106, 0.08);
            color: var(--error);
        }
        .alert-success {
            border: 1px solid var(--accent-line);
            background: var(--accent-soft);
            color: var(--accent);
        }

        /* DROITE — marque */
        .pane-brand {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 48px;
            background: var(--panel-2);
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .pane-brand::before {
            content: '';
            position: absolute;
            inset: 0;
            background: radial-gradient(
                ellipse 60% 45% at 50% 40%,
                rgba(218, 119, 81, 0.07),
                transparent 70%
            );
            pointer-events: none;
        }

        .brand-stack { position: relative; z-index: 1; }

        .brand-logo {
            width: 96px;
            height: 96px;
            border-radius: 16px;
            margin-bottom: 30px;
            box-shadow: 0 8px 40px rgba(218, 119, 81, 0.18);
        }

        .ascii-banner {
            color: #b75f40;
            font-size: clamp(6px, 1.1vw, 12px);
            line-height: 1.18;
            text-shadow: 0 0 14px rgba(218, 119, 81, 0.35);
            white-space: pre;
            overflow: hidden;
            user-select: none;
            margin-bottom: 18px;
        }

        .ascii-dog {
            color: var(--accent);
            opacity: 0.75;
            font-size: clamp(5px, 0.95vw, 10.5px);
            line-height: 1.25;
            white-space: pre;
            overflow: hidden;
            user-select: none;
            margin-bottom: 26px;
        }

        .brand-tagline {
            font-size: 13px;
            color: var(--muted);
            letter-spacing: 0.06em;
            line-height: 1.7;
        }
        .brand-tagline em { color: var(--accent); font-style: normal; }

        .brand-specs {
            margin-top: 28px;
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            justify-content: center;
        }
        .spec {
            font-size: 10.5px;
            letter-spacing: 0.08em;
            color: var(--faint);
            border: 1px solid var(--line);
            padding: 5px 10px;
            border-radius: 4px;
        }

        @media (max-width: 900px) {
            .shell { grid-template-columns: 1fr; }
            .pane-brand { display: none; }
            .pane-form { border-right: none; padding: 40px 24px; }
        }
    </style>
</head>
<body>
<!-- Google Tag Manager (noscript) -->
<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-MK76ZMD6"
height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>
<!-- End Google Tag Manager (noscript) -->
    <div class="shell">
        <section class="pane-form">
            <div class="form-inner">
                <div class="brand-mini">
                    <img src="/static/logo.svg" alt="Cerbere">
                    <span>CERBERE</span>
                </div>

                <div class="welcome">
                    <h1>Sign in</h1>
                    <p>Access your runtime security console.</p>
                </div>

                <div class="prompt-line"><span class="sig">cerbere@gate</span>:~$ auth --identity human</div>

                <div id="alert-box"></div>

                <form id="otp-form">
                    <label class="field-label" for="email">work_email</label>
                    <input type="email" id="email" placeholder="you@company.com" required autocomplete="email">
                    <button type="submit" class="btn" id="otp-btn">Send magic link</button>
                </form>

                <div class="rule">OR CONTINUE WITH</div>

                <div class="oauth-row">
                    <button class="btn btn-oauth" id="btn-google">
                        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                            <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                            <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                            <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                        </svg>
                        Continue with Google
                    </button>
                    <button class="btn btn-oauth" id="btn-github">
                        <svg viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
                            <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
                        </svg>
                        Continue with GitHub
                    </button>
                </div>

                <p class="signup-note">
                    <strong>No sign-up needed</strong> — enter your email or use Google / GitHub
                    and Cerbere provisions your workspace automatically.
                </p>
            </div>
        </section>
        <section class="pane-brand">
            <div class="brand-stack">
                <img src="/static/logo.svg" alt="Cerbere" class="brand-logo">
<pre class="ascii-banner">
 ██████╗███████╗██████╗ ██████╗ ███████╗██████╗ ███████╗
██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝
██║     █████╗  ██████╔╝██████╔╝█████╗  ██████╔╝█████╗
██║     ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗██╔══╝
╚██████╗███████╗██║  ██║██████╔╝███████╗██║  ██║███████╗
 ╚═════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝</pre>
<pre class="ascii-dog">
     /\\___/\\     /\\___/\\     /\\___/\\
    ( o   o )   ( o   o )   ( o   o )
     (  =^= )    (  =^= )    (  =^= )
 ___/ \\___/ ____ \\___/ ____ \\___/ \\___</pre>
                <p class="brand-tagline">
                    The <em>Three-Headed Guardian</em> of AI agents.<br>
                    Runtime security, observability and audit for your stack.
                </p>
                <div class="brand-specs">
                    <span class="spec">runtime security</span>
                    <span class="spec">observability</span>
                    <span class="spec">rbac + audit</span>
                    <span class="spec">sub-ms checks</span>
                </div>
            </div>
        </section>
    </div>

    <script>
        const supabaseClient = window.supabase.createClient(
            "{{ supabase_url }}",
            "{{ supabase_anon_key }}"
        );

        function showAlert(msg, kind) {
            const box = document.getElementById("alert-box");
            if (box) box.innerHTML = `<div class="alert alert-${kind}">${msg}</div>`;
        }

        const otpForm = document.getElementById("otp-form");
        if (otpForm) {
            otpForm.addEventListener("submit", async (e) => {
                e.preventDefault();
                const email = document.getElementById("email").value.trim();
                const btn = document.getElementById("otp-btn");
                btn.disabled = true;
                btn.textContent = "Sending...";

                const { error } = await supabaseClient.auth.signInWithOtp({
                    email,
                    options: { emailRedirectTo: window.location.origin + "/login" }
                });

                btn.disabled = false;
                btn.textContent = "Send magic link";

                if (error) {
                    showAlert(error.message, "error");
                } else {
                    showAlert("Check your inbox — your secure sign-in link is on its way.", "success");
                }
            });
        }

        const btnGoogle = document.getElementById("btn-google");
        if (btnGoogle) {
            btnGoogle.addEventListener("click", () => {
                supabaseClient.auth.signInWithOAuth({
                    provider: "google",
                    options: { redirectTo: window.location.origin + "/login" }
                });
            });
        }

        const btnGithub = document.getElementById("btn-github");
        if (btnGithub) {
            btnGithub.addEventListener("click", () => {
                supabaseClient.auth.signInWithOAuth({
                    provider: "github",
                    options: { redirectTo: window.location.origin + "/login" }
                });
            });
        }

        async function handleMagicLinkReturn() {
            await new Promise(resolve => setTimeout(resolve, 150));
            const { data: { session } } = await supabaseClient.auth.getSession();

            if (session && session.access_token) {
                showAlert("Signing you in...", "success");

                try {
                    const resp = await fetch("/api/auth/supabase-session", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        credentials: "include",
                        body: JSON.stringify({ access_token: session.access_token })
                    });

                    if (resp.ok) {
                        window.location.href = "/";
                    } else {
                        const body = await resp.json().catch(() => ({}));
                        showAlert(body.error || "Sign-in failed.", "error");
                        window.history.replaceState({}, document.title, "/login");
                    }
                } catch (err) {
                    showAlert("Network error during sign-in.", "error");
                    window.history.replaceState({}, document.title, "/login");
                }
            }
        }

        handleMagicLinkReturn();

        supabaseClient.auth.onAuthStateChange((event, session) => {
            if (event === 'SIGNED_IN' && session) {
                handleMagicLinkReturn();
            }
        });
    </script>
</body>
</html>
"""


LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CERBERE — Sign in</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        :root {
            --bg: #121110;
            --panel: #171512;
            --panel-2: #1c1915;
            --accent: #da7751;
            --accent-soft: rgba(218, 119, 81, 0.12);
            --accent-line: rgba(218, 119, 81, 0.30);
            --text: #ece6db;
            --muted: #8f8579;
            --faint: #5c554c;
            --error: #d96a6a;
            --line: rgba(236, 230, 219, 0.09);
        }

        body {
            font-family: 'JetBrains Mono', 'Courier New', monospace;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            -webkit-font-smoothing: antialiased;
        }

        .shell {
            display: grid;
            grid-template-columns: minmax(420px, 500px) 1fr;
            min-height: 100vh;
        }

        /* GAUCHE — formulaire */
        .pane-form {
            display: flex;
            flex-direction: column;
            justify-content: center;
            padding: 48px 52px;
            background: var(--panel);
            border-right: 1px solid var(--line);
        }

        .form-inner { width: 100%; max-width: 380px; margin: 0 auto; }

        .brand-mini {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 42px;
        }
        .brand-mini img { width: 26px; height: 26px; border-radius: 5px; }
        .brand-mini span {
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 0.22em;
            color: var(--text);
        }

        .welcome h1 {
            font-size: 22px;
            font-weight: 700;
            margin-bottom: 8px;
        }
        .welcome p {
            font-size: 13px;
            color: var(--muted);
            line-height: 1.6;
            margin-bottom: 30px;
        }

        .prompt-line {
            font-size: 12px;
            color: var(--faint);
            margin-bottom: 18px;
        }
        .prompt-line .sig { color: #b75f40; }

        .field-label {
            display: block;
            font-size: 12px;
            color: var(--muted);
            margin-bottom: 7px;
        }
        .field-label::before { content: '> '; color: var(--accent); }

        input[type="email"], input[type="text"] {
            width: 100%;
            padding: 12px 14px;
            background: var(--bg);
            border: 1px solid var(--line);
            color: var(--text);
            font-family: inherit;
            font-size: 13.5px;
            outline: none;
            border-radius: 6px;
            caret-color: var(--accent);
            transition: border-color .15s ease, box-shadow .15s ease;
        }
        input:focus {
            border-color: var(--accent-line);
            box-shadow: 0 0 0 3px var(--accent-soft);
        }
        input::placeholder { color: var(--faint); }

        .btn {
            width: 100%;
            padding: 12px;
            font-family: inherit;
            font-size: 12.5px;
            font-weight: 700;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            cursor: pointer;
            border-radius: 6px;
            border: 1px solid var(--accent);
            background: var(--accent);
            color: #1a120c;
            transition: all .15s ease;
            margin-top: 14px;
        }
        .btn:hover:not(:disabled) { filter: brightness(1.08); }
        .btn:active:not(:disabled) { transform: translateY(1px); }
        .btn:disabled { opacity: 0.5; cursor: default; }

        .rule {
            display: flex;
            align-items: center;
            gap: 14px;
            margin: 22px 0;
            color: var(--faint);
            font-size: 10.5px;
            letter-spacing: 0.22em;
            user-select: none;
        }
        .rule::before, .rule::after {
            content: '';
            flex: 1;
            height: 1px;
            background: var(--line);
        }

        .oauth-row { display: flex; flex-direction: column; gap: 10px; }

        .btn-oauth {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            background: transparent;
            color: var(--text);
            border: 1px solid var(--line);
            margin-top: 0;
        }
        .btn-oauth:hover:not(:disabled) {
            border-color: var(--accent-line);
            background: var(--accent-soft);
            color: var(--text);
            filter: none;
        }
        .btn-oauth svg { width: 15px; height: 15px; flex-shrink: 0; }

        .signup-note {
            margin-top: 26px;
            padding-top: 20px;
            border-top: 1px solid var(--line);
            font-size: 11.5px;
            color: var(--faint);
            line-height: 1.7;
        }
        .signup-note strong { color: var(--muted); }

        .signup-link {
            margin-top: 20px;
            font-size: 12px;
            color: var(--muted);
        }
        .signup-link a { color: var(--accent); text-decoration: none; }
        .signup-link a:hover { text-decoration: underline; }

        .alert {
            padding: 11px 14px;
            font-size: 12.5px;
            line-height: 1.6;
            margin-bottom: 18px;
            border-radius: 6px;
            font-family: inherit;
        }
        .alert-error {
            border: 1px solid rgba(217, 106, 106, 0.4);
            background: rgba(217, 106, 106, 0.08);
            color: var(--error);
        }
        .alert-success {
            border: 1px solid var(--accent-line);
            background: var(--accent-soft);
            color: var(--accent);
        }

        /* DROITE — marque */
        .pane-brand {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 48px;
            background: var(--panel-2);
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .pane-brand::before {
            content: '';
            position: absolute;
            inset: 0;
            background: radial-gradient(
                ellipse 60% 45% at 50% 40%,
                rgba(218, 119, 81, 0.07),
                transparent 70%
            );
            pointer-events: none;
        }

        .brand-stack { position: relative; z-index: 1; }

        .brand-logo {
            width: 96px;
            height: 96px;
            border-radius: 16px;
            margin-bottom: 30px;
            box-shadow: 0 8px 40px rgba(218, 119, 81, 0.18);
        }

        .ascii-banner {
            color: var(--accent);
            font-size: clamp(6px, 1.1vw, 12px);
            line-height: 1.18;
            text-shadow: 0 0 14px rgba(218, 119, 81, 0.35);
            white-space: pre;
            overflow: hidden;
            user-select: none;
            margin-bottom: 18px;
        }

        .ascii-dog {
            color: #b75f40;
            opacity: 0.75;
            font-size: clamp(5px, 0.95vw, 10.5px);
            line-height: 1.25;
            white-space: pre;
            overflow: hidden;
            user-select: none;
            margin-bottom: 26px;
        }

        .brand-tagline {
            font-size: 13px;
            color: var(--muted);
            letter-spacing: 0.06em;
            line-height: 1.7;
        }
        .brand-tagline em { color: #b75f40; font-style: normal; }

        .brand-specs {
            margin-top: 28px;
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            justify-content: center;
        }
        .spec {
            font-size: 10.5px;
            letter-spacing: 0.08em;
            color: var(--faint);
            border: 1px solid var(--line);
            padding: 5px 10px;
            border-radius: 4px;
        }

        @media (max-width: 900px) {
            .shell { grid-template-columns: 1fr; }
            .pane-brand { display: none; }
            .pane-form { border-right: none; padding: 40px 24px; }
        }

        .tabs {
            display: flex;
            gap: 0;
            margin-bottom: 18px;
            border: 1px solid var(--line);
            border-radius: 6px;
            overflow: hidden;
            user-select: none;
        }
        .tab {
            flex: 1;
            padding: 10px;
            background: transparent;
            border: none;
            border-right: 1px solid var(--line);
            color: var(--muted);
            font-family: inherit;
            font-size: 11.5px;
            letter-spacing: 0.1em;
            cursor: pointer;
            transition: all .15s ease;
        }
        .tab:last-child { border-right: none; }
        .tab.active { background: var(--accent-soft); color: var(--accent); }
        .tab:hover:not(.active) { color: var(--text); }

        .auth-form { display: none; }
        .auth-form.active { display: block; animation: fadeIn 0.25s ease; }
        .form-group { margin-bottom: 14px; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

        .oauth-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }

        @media (max-width: 480px) {
            .oauth-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="shell">
        <section class="pane-form">
            <div class="form-inner">
                <div class="brand-mini">
                    <img src="/static/logo.svg" alt="Cerbere">
                    <span>CERBERE</span>
                </div>

                <div class="welcome">
                    <h1>Sign in</h1>
                    <p>Access your runtime security console.</p>
                </div>

                <div class="prompt-line"><span class="sig">cerbere@gate</span>:~$ auth --identity human</div>

                {% if error %}
                <div class="alert alert-error">ERR: {{ error }}</div>
                {% endif %}

                {% if success %}
                <div class="alert alert-success">OK: {{ success }}</div>
                {% endif %}

                <div class="tabs">
                    <button class="tab active" onclick="switchTab('email')" id="tab-email">WORK EMAIL</button>
                    <button class="tab" onclick="switchTab('sso')" id="tab-sso">ENTERPRISE SSO</button>
                </div>

                <form class="auth-form active" id="email-form" method="post" action="/login">
                    <div class="form-group">
                        <label class="field-label" for="email">work_email</label>
                        <input type="email" id="email" name="email" placeholder="name@company.com" required autocomplete="email" autocapitalize="none">
                    </div>
                    <button type="submit" class="btn">Send magic link</button>
                </form>

                <form class="auth-form" id="sso-form" method="post" action="/login">
                    <div class="form-group">
                        <label class="field-label" for="company-domain">company_domain</label>
                        <input type="text" id="company-domain" name="domain" placeholder="company.com" required>
                    </div>
                    <div class="form-group">
                        <label class="field-label" for="sso-email">work_email</label>
                        <input type="email" id="sso-email" name="email" placeholder="name@company.com" required>
                    </div>
                    <button type="submit" class="btn">Continue with SSO</button>
                </form>

                <div class="rule">OR CONTINUE WITH</div>

                <div class="oauth-grid">
                    <a href="/auth/google" class="btn btn-oauth">
                        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                            <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                            <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                            <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                        </svg>
                        Google
                    </a>
                    <a href="/auth/github" class="btn btn-oauth">
                        <svg viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
                            <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
                        </svg>
                        GitHub
                    </a>
                </div>

                <div class="signup-link">
                    No account yet? <a href="/signup">./signup</a>
                </div>
            </div>
        </section>
        <section class="pane-brand">
            <div class="brand-stack">
                <img src="/static/logo.svg" alt="Cerbere" class="brand-logo">
<pre class="ascii-banner">
 ██████╗███████╗██████╗ ██████╗ ███████╗██████╗ ███████╗
██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝
██║     █████╗  ██████╔╝██████╔╝█████╗  ██████╔╝█████╗
██║     ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗██╔══╝
╚██████╗███████╗██║  ██║██████╔╝███████╗██║  ██║███████╗
 ╚═════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝</pre>
<pre class="ascii-dog">
     /\\___/\\     /\\___/\\     /\\___/\\
    ( o   o )   ( o   o )   ( o   o )
     (  =^= )    (  =^= )    (  =^= )
 ___/ \\___/ ____ \\___/ ____ \\___/ \\___</pre>
                <p class="brand-tagline">
                    The <em>Three-Headed Guardian</em> of AI agents.<br>
                    Runtime security, observability and audit for your stack.
                </p>
                <div class="brand-specs">
                    <span class="spec">runtime security</span>
                    <span class="spec">observability</span>
                    <span class="spec">rbac + audit</span>
                    <span class="spec">sub-ms checks</span>
                </div>
            </div>
        </section>
    </div>

    <script>
        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));

            if (tab === 'email') {
                document.getElementById('tab-email').classList.add('active');
                document.getElementById('email-form').classList.add('active');
            } else {
                document.getElementById('tab-sso').classList.add('active');
                document.getElementById('sso-form').classList.add('active');
            }
        }
    </script>
</body>
</html>
"""


SIGNUP_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cerbere — Create Account</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        /* Mêmes variables et styles que la page de login pour une cohérence totale */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg-primary: #09090b; --bg-secondary: #18181b;
            --border-color: rgba(255, 255, 255, 0.08); --border-hover: rgba(239, 68, 68, 0.5);
            --text-primary: #fafafa; --text-secondary: #a1a1aa; --text-muted: #71717a;
            --accent-red: #ef4444; --accent-orange: #f97316; --accent-glow: rgba(239, 68, 68, 0.15);
            --success: #10b981;
        }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary); color: var(--text-primary);
            min-height: 100vh; overflow-x: hidden; -webkit-font-smoothing: antialiased;
        }
        .container { display: grid; grid-template-columns: 1fr 1fr; min-height: 100vh; }
        .login-section {
            display: flex; flex-direction: column; justify-content: center; align-items: center;
            padding: 3rem; background: var(--bg-primary); position: relative;
        }
        .login-container { width: 100%; max-width: 420px; position: relative; z-index: 1; }
        .logo { display: flex; align-items: center; gap: 12px; margin-bottom: 2.5rem; }
        .logo img { width: 40px; height: 40px; }
        .logo-text { font-size: 22px; font-weight: 700; letter-spacing: -0.02em; color: var(--text-primary); }
        .welcome-text { margin-bottom: 2rem; }
        .welcome-text h1 { font-size: 28px; font-weight: 600; margin-bottom: 0.5rem; letter-spacing: -0.02em; }
        .welcome-text p { color: var(--text-secondary); font-size: 15px; line-height: 1.5; }
        .form-group { margin-bottom: 1.25rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; font-size: 13px; font-weight: 500; color: var(--text-secondary); }
        .form-group input {
            width: 100%; padding: 12px 14px; background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-primary);
            font-size: 14px; transition: all 0.2s ease; outline: none;
        }
        .form-group input:focus {
            border-color: var(--border-hover); background: rgba(255, 255, 255, 0.05);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }
        .form-group input::placeholder { color: var(--text-muted); }
        .btn-primary {
            width: 100%; padding: 12px; background: var(--text-primary); border: none;
            border-radius: 8px; color: var(--bg-primary); font-size: 14px; font-weight: 600;
            cursor: pointer; transition: all 0.2s ease;
        }
        .btn-primary:hover { background: #e4e4e7; }
        .btn-primary:active { transform: scale(0.98); }
        .signup-link { text-align: center; margin-top: 1.5rem; color: var(--text-secondary); font-size: 14px; }
        .signup-link a { color: var(--text-primary); text-decoration: none; font-weight: 500; transition: color 0.2s ease; }
        .signup-link a:hover { text-decoration: underline; }
        .security-badge {
            display: flex; align-items: center; justify-content: center; gap: 8px;
            margin-top: 2rem; padding: 10px; background: rgba(16, 185, 129, 0.05);
            border: 1px solid rgba(16, 185, 129, 0.15); border-radius: 6px;
            color: var(--success); font-size: 12px; font-weight: 500; letter-spacing: 0.02em;
        }
        .security-badge::before {
            content: ''; width: 6px; height: 6px; background: var(--success);
            border-radius: 50%; box-shadow: 0 0 8px var(--success); animation: pulse-dot 2s infinite;
        }
        @keyframes pulse-dot { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
        .alert { padding: 12px 16px; border-radius: 8px; font-size: 14px; margin-bottom: 1.5rem; line-height: 1.5; animation: fadeIn 0.3s ease; }
        .alert-error { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); color: #f87171; }
        .alert-success { background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); color: #34d399; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }
        
        /* Hero Section (identique à login) */
        .hero-section {
            position: relative; display: flex; flex-direction: column; justify-content: center;
            align-items: center; padding: 3rem; background: var(--bg-secondary);
            overflow: hidden; border-left: 1px solid var(--border-color);
        }
        .hero-bg { position: absolute; top: 0; left: 0; right: 0; bottom: 0; overflow: hidden; }
        .wave-container { position: absolute; width: 100%; height: 100%; }
        .wave {
            position: absolute; width: 150%; height: 150%; top: -25%; left: -25%;
            background: radial-gradient(circle, rgba(239, 68, 68, 0.08) 0%, transparent 60%);
            border-radius: 40%; animation: rotate 30s linear infinite; transition: transform 0.1s ease-out;
        }
        .wave:nth-child(2) { background: radial-gradient(circle, rgba(249, 115, 22, 0.06) 0%, transparent 60%); animation-delay: -10s; animation-duration: 40s; }
        .wave:nth-child(3) { background: radial-gradient(circle, rgba(239, 68, 68, 0.04) 0%, transparent 60%); animation-delay: -20s; animation-duration: 50s; }
        @keyframes rotate { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        .grid-overlay {
            position: absolute; top: 0; left: 0; right: 0; bottom: 0;
            background-image: linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
            background-size: 40px 40px; mask-image: radial-gradient(circle at center, black 40%, transparent 80%);
        }
        .hero-content { position: relative; z-index: 1; text-align: center; max-width: 560px; }
        .hero-logo { width: 80px; height: 80px; margin-bottom: 2rem; filter: drop-shadow(0 0 40px rgba(239, 68, 68, 0.2)); transition: transform 0.5s ease; }
        .hero-section:hover .hero-logo { transform: scale(1.05); }
        .hero-title { font-size: 36px; font-weight: 700; margin-bottom: 1rem; line-height: 1.2; letter-spacing: -0.02em; color: var(--text-primary); }
        .hero-title span { background: linear-gradient(135deg, var(--accent-red) 0%, var(--accent-orange) 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        .hero-subtitle { font-size: 16px; color: var(--text-secondary); line-height: 1.6; margin-bottom: 3rem; }
        .hero-features { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; text-align: left; }
        .feature { padding: 16px; background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 8px; transition: all 0.3s ease; }
        .feature:hover { border-color: rgba(239, 68, 68, 0.3); background: rgba(255, 255, 255, 0.04); }
        .feature-icon { width: 32px; height: 32px; margin-bottom: 12px; color: var(--accent-red); }
        .feature h3 { font-size: 14px; font-weight: 600; margin-bottom: 4px; color: var(--text-primary); }
        .feature p { font-size: 13px; color: var(--text-muted); line-height: 1.4; }
        @media (max-width: 968px) { .container { grid-template-columns: 1fr; } .hero-section { display: none; } .login-section { padding: 2rem; } }
    </style>
</head>
<body>
    <div class="container">
        <section class="login-section">
            <div class="login-container">
                <div class="logo">
                    <img src="/static/logo.svg" alt="Cerbere Logo">
                    <span class="logo-text">CERBERE</span>
                </div>

                <div class="welcome-text">
                    <h1>Create your account</h1>
                    <p>Start securing your AI agents in minutes.</p>
                </div>

                {% if error %}
                <div class="alert alert-error">{{ error }}</div>
                {% endif %}

                {% if success %}
                <div class="alert alert-success">{{ success }}</div>
                {% endif %}

                <form class="auth-form active" method="post" action="/signup">
                    <div class="form-group">
                        <label for="name">Full Name</label>
                        <input type="text" id="name" name="name" placeholder="John Doe" required autocomplete="name">
                    </div>
                    <div class="form-group">
                        <label for="email">Work Email</label>
                        <input type="email" id="email" name="email" placeholder="name@company.com" required autocomplete="email" autocapitalize="none">
                    </div>
                    <div class="form-group">
                        <label for="company">Company Name <span style="color: var(--text-muted); font-weight: 400;">(Optional)</span></label>
                        <input type="text" id="company" name="company" placeholder="Acme Inc." autocomplete="organization">
                    </div>
                    <button type="submit" class="btn-primary">Create account & send link</button>
                </form>

                <div class="signup-link">
                    Already have an account? <a href="/login">Sign in</a>
                </div>

                <div class="security-badge">SOC 2 Type II Compliant</div>
            </div>
        </section>

        <section class="hero-section" id="hero-section">
            <div class="hero-bg">
                <div class="wave-container">
                    <div class="wave"></div><div class="wave"></div><div class="wave"></div>
                </div>
                <div class="grid-overlay"></div>
            </div>
            <div class="hero-content">
                <img src="/static/logo.svg" alt="Cerbere" class="hero-logo">
                <h1 class="hero-title">Cerbere &mdash; The Three-Headed <span>Guardian</span> of AI Agents</h1>
                <p class="hero-subtitle">Advanced runtime security and observability for AI agents. Monitor, detect, and protect your AI infrastructure in real-time.</p>
                <div class="hero-features">
                    <div class="feature">
                        <svg class="feature-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                        <h3>Runtime Security</h3><p>Real-time threat detection and policy enforcement.</p>
                    </div>
                    <div class="feature">
                        <svg class="feature-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                        <h3>Observability</h3><p>Complete visibility into agent behavior and decisions.</p>
                    </div>
                    <div class="feature">
                        <svg class="feature-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                        <h3>Access Control</h3><p>Granular RBAC and audit trails for compliance.</p>
                    </div>
                    <div class="feature">
                        <svg class="feature-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                        <h3>Low Latency</h3><p>Sub-millisecond security checks without blocking.</p>
                    </div>
                </div>
            </div>
        </section>
    </div>
    <script>
        const heroSection = document.getElementById('hero-section');
        const waves = document.querySelectorAll('.wave');
        if (heroSection && waves.length > 0) {
            heroSection.addEventListener('mousemove', (e) => {
                const rect = heroSection.getBoundingClientRect();
                const x = (e.clientX - rect.left) / rect.width - 0.5;
                const y = (e.clientY - rect.top) / rect.height - 0.5;
                waves.forEach((wave, index) => {
                    const speed = (index + 1) * 15;
                    wave.style.transform = `translate(${x * speed}px, ${y * speed}px)`;
                });
            });
            heroSection.addEventListener('mouseleave', () => {
                waves.forEach(wave => { wave.style.transform = 'translate(0, 0)'; });
            });
        }
    </script>
</body>
</html>
"""
