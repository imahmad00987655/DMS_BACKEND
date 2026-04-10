# 🚀 Hostinger Deployment Guide - Step by Step

## 📋 Prerequisites
- GitHub account
- Hostinger account with Node.js support
- Gmail account (for email service)

---

## Step 1: GitHub Par Code Push Karein

### 1.1 Git Initialize Karein (agar pehle se nahi hai)
```bash
cd fluent-financial-flow
git init
```

### 1.2 .gitignore Check Karein
- Root folder me `.gitignore` file hai
- `backend/.env` aur `frontend/.env*` files ignore ho rahi hain (✅ safe)

### 1.3 GitHub Repository Create Karein
1. GitHub.com par jao
2. "New repository" click karo
3. Repository name: `fluent-financial-flow` (ya jo chaho)
4. **Public** ya **Private** select karo
5. "Create repository" click karo

### 1.4 Code Push Karein
```bash
# All files add karo (except .env files - wo automatically ignore ho jayengi)
git add .

# Commit karo
git commit -m "Initial commit - Ready for Hostinger deployment"

# GitHub remote add karo (apna repository URL use karo)
git remote add origin https://github.com/YOUR_USERNAME/fluent-financial-flow.git

# Push karo
git branch -M main
git push -u origin main
```

✅ **Check:** GitHub par code push ho gaya hai, `.env` files nahi dikhni chahiye

---

## Step 2: Hostinger Me GitHub Connect Karein

### 2.1 Hostinger hPanel Me Jao
1. Hostinger hPanel login karo
2. **"Websites"** section me jao
3. **"Create Website"** ya **"Add Website"** click karo

### 2.2 GitHub Integration Select Karein
1. **"GitHub"** option select karo
2. GitHub account se connect karo (permission de do)
3. Apna repository select karo: `fluent-financial-flow`

### 2.3 Backend Node.js App Setup
Hostinger me **Node.js App** create karo:

**Settings:**
- **App Name:** `fluent-financial-flow-backend`
- **App Root:** `backend` (important!)
- **Entry File:** `server.js`
- **Node Version:** Latest LTS (18.x ya 20.x)
- **Start Command:** `npm start`
- **Build Command:** `npm install` (pehle se run ho jayega)

✅ **Note:** Abhi database create nahi karein, pehle app setup complete karo

---

## Step 3: Database Create Karein (Hostinger Me)

### 3.1 MySQL Database Create
1. Hostinger hPanel me **"MySQL Databases"** section me jao
2. **"Create Database"** click karo
3. Database details note karo:
   - **Database Name:** `u123456789_fluent` (example)
   - **Database User:** `u123456789_fluent_user`
   - **Database Password:** (apna strong password set karo)
   - **Host:** Usually `localhost` (ya jo Hostinger ne diya ho)

### 3.2 Database Schema Import Karein
1. **phpMyAdmin** open karo (Hostinger hPanel se)
2. Apna database select karo
3. **"Import"** tab click karo
4. `backend/database/schema.sql` file upload karo
5. **"Go"** click karo

✅ **Check:** Database tables create ho gaye hain

---

## Step 4: Environment Variables Set Karein (Hostinger Me)

### 4.1 Hostinger Node.js App Me Env Variables Add Karein
Hostinger ke Node.js app settings me **"Environment Variables"** section me ye add karo:

```env
# Server Configuration
NODE_ENV=production
PORT=5000

# Database Configuration (Hostinger MySQL credentials)
DB_HOST=localhost
DB_USER=u123456789_fluent_user
DB_PASSWORD=your-database-password
DB_NAME=u123456789_fluent
DB_PORT=3306

# JWT Configuration
JWT_SECRET=your-very-strong-random-secret-key-change-this
JWT_EXPIRES_IN=7d

# Email Configuration (Gmail - wahi rahega)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=imahmadkhan1029@gmail.com
EMAIL_PASS=your-16-char-gmail-app-password
EMAIL_FROM=imahmadkhan1029@gmail.com

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# CORS Configuration (Production Frontend Domain)
CORS_ORIGIN=https://your-frontend-domain.com
```

### 4.2 Important Notes:
- **DB_HOST, DB_USER, DB_PASSWORD, DB_NAME:** Hostinger MySQL ke exact credentials use karo
- **EMAIL_PASS:** Gmail App Password (16 characters) - [EMAIL_SETUP.md](frontend/EMAIL_SETUP.md) follow karo
- **CORS_ORIGIN:** Apna production frontend domain (agar abhi nahi pata, pehle `http://localhost:5173` rakh do, baad me update kar lena)
- **JWT_SECRET:** Strong random string (example: `openssl rand -base64 32` se generate karo)

---

## Step 5: Backend App Start Karein

### 5.1 Hostinger Me App Deploy Karein
1. Node.js app settings me **"Deploy"** ya **"Start"** button click karo
2. Hostinger automatically `npm install` run karega
3. Phir `npm start` se server start hoga

### 5.2 Check Logs
Hostinger ke **"Logs"** section me check karo:
- ✅ `🚀 Server running on port 5000`
- ✅ `✅ Database connected successfully`
- ✅ `✅ Email service configured successfully` (ya warning agar email setup nahi hai)

### 5.3 Test Backend
Browser me test karo:
- `https://your-backend-domain.com/health` → Should return `{"success": true, ...}`
- `https://your-backend-domain.com/test-db` → Should return database connection status

---

## Step 6: Frontend Setup (Agar Chaho)

Frontend ke liye alag se guide chahiye to batao, lekin basic steps:

1. **Frontend Build:** Locally `npm run build` karo
2. **Static Site:** Hostinger me static site create karo, `frontend/dist` folder upload karo
3. **API URL:** Frontend me backend URL update karo (next step me detail)

---

## ✅ Checklist - Deployment Complete

- [ ] GitHub par code push ho gaya
- [ ] Hostinger me GitHub repo connect ho gaya
- [ ] Node.js app create ho gaya (`backend` folder as root)
- [ ] MySQL database create ho gaya
- [ ] Database schema import ho gaya
- [ ] Environment variables set ho gaye (sab kuch)
- [ ] Backend app start ho gaya
- [ ] Health check pass ho gaya (`/health` endpoint)
- [ ] Database connection test pass ho gaya (`/test-db` endpoint)
- [ ] Email service configured (logs me check karo)

---

## 🆘 Troubleshooting

### Database Connection Error
- Check: `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` sahi hain?
- Check: Database user ko proper permissions hain?
- Check: `DB_HOST` me `localhost` ya exact host name?

### Email Service Error
- Check: Gmail App Password sahi hai? (16 characters)
- Check: 2FA enabled hai Gmail account me?
- Check: `EMAIL_USER` aur `EMAIL_FROM` same email hai?

### CORS Error
- Check: `CORS_ORIGIN` me frontend domain sahi hai?
- Check: Frontend se request sahi URL par ja rahi hai?

### Port Error
- Check: `PORT` env variable sahi hai?
- Check: Hostinger ka internal port kya hai?

---

## 📞 Next Steps

1. **Frontend deploy** karo (agar chaho)
2. **Domain connect** karo (agar custom domain hai)
3. **SSL certificate** enable karo (HTTPS ke liye)
4. **Monitoring setup** karo (logs, errors track karo)

---

**Need Help?** Koi step me issue ho to batao! 🚀

