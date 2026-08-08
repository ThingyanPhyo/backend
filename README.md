# Overtime Tracker OTP Backend (Cloudflare Workers + Brevo)

Render ရဲ့အစား — **sleep လုံးဝမရှိတဲ့** Cloudflare Workers ပေါ်မှာ run ဖို့ ရေးထားတဲ့ backend ပါ။
Email ပို့ဖို့ [Brevo](https://www.brevo.com) (free, 300 email/day, domain မလိုပါ — sender
email address တစ်ခုပဲ verify လုပ်ရုံပါ) ကို သုံးထားပါတယ်။ OTP တွေကို Cloudflare Workers KV
(free) ထဲမှာ သိမ်းထားပါတယ်။

## 1) Cloudflare account + wrangler

```bash
cd backend
npm install
npx wrangler login   # browser ဖွင့်ပြီး Cloudflare account နဲ့ login
```

## 2) KV namespace ဖန်တီးမယ်

```bash
npx wrangler kv namespace create OTP_KV
```

Terminal ထဲမှာ ပြန်ထွက်လာတဲ့ `id = "xxxxxxxx"` ကို ကူးပြီး `wrangler.toml` ထဲက
`REPLACE_WITH_YOUR_KV_NAMESPACE_ID` နေရာမှာ ထည့်ပါ။

## 3) Brevo setup

1. https://www.brevo.com မှာ account အလကားဖွင့်ပါ
2. **Senders, Domains & Dedicated IPs → Senders → Add a Sender** မှာ email address
   တစ်ခု (ဥပမာ သင့် Gmail) ထည့်ပါ — Brevo က confirm link ပို့ပါလိမ့်မယ်၊ click လုပ်ပြီး verify လုပ်ပါ
   (domain verify စရာ **မလိုပါ**)
3. **SMTP & API → API Keys** မှာ API key အသစ်တစ်ခု ထုတ်ပါ

## 4) Secrets ထည့်မယ်

```bash
npx wrangler secret put BREVO_API_KEY
# (paste လုပ်ပါ — step 3 က API key)

npx wrangler secret put SENDER_EMAIL
# (paste လုပ်ပါ — step 2 က verify လုပ်ပြီးသား sender email)
```

## 5) Deploy

```bash
npx wrangler deploy
```

Deploy ပြီးရင် URL တစ်ခု ပြပါလိမ့်မယ်
(ဥပမာ `https://overtime-tracker-otp.<your-subdomain>.workers.dev`) — ဒီ URL ကို
`app/src/main/java/com/overtime/tracker/ApiClient.kt` ထဲက `BASE_URL` မှာ ထည့်ပြီး
app ကို ပြန် build လုပ်ပါ။

## စစ်ဆေးနည်း

Browser ထဲမှာ backend URL ကို ဖွင့်ကြည့်ရင် `{"success":true,"message":"Overtime Tracker OTP
service is running."}` ဆိုတာ ချက်ချင်း (delay မရှိဘဲ) ပြရပါမယ် — Render နဲ့ မတူတာက ဒီအချက်ပါပဲ
(cold-start စောင့်စရာ မလိုတော့ပါ)။

## Free tier ဘယ်လောက်လုံလောက်လဲ

- Cloudflare Workers: 100,000 requests/day free
- Cloudflare KV: 100,000 reads/day, 1,000 writes/day free
- Brevo: 300 emails/day free, no expiry

User ဆယ်ဂဏန်းလောက်၊ occasional login/verify အတွက်ဆိုရင် ဒီ free tier တွေက အလွန်လုံလောက်ပါတယ်။
