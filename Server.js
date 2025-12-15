const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

// ========== LOAD ENVIRONMENT VARIABLES ==========
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ========== VERCEL COMPATIBILITY ==========
const isVercel = process.env.VERCEL === '1';

// ========== SUPABASE SETUP ==========
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'your-fallback-secret-change-in-production';
const ADMIN_INIT_KEY = process.env.ADMIN_INIT_KEY || 'init-key-change-this';

// Validate environment variables
if (!SUPABASE_URL || !SUPABASE_KEY) {
    console.error('❌ ERROR: Missing Supabase credentials');
    console.error('   Set SUPABASE_URL and SUPABASE_KEY environment variables');
    console.error('   For Vercel: Add them in Project Settings > Environment Variables');
    console.error('   For Local: Create a .env file with these variables');
    process.exit(1);
}

if (!JWT_SECRET || JWT_SECRET === 'your-fallback-secret-change-in-production') {
    console.warn('⚠️  WARNING: Using default JWT secret. Set JWT_SECRET in environment for production.');
}

// Create Supabase client with connection pooling
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
    auth: {
        persistSession: false
    }
});

console.log('✅ Connected to Supabase');

// ========== PERFORMANCE OPTIMIZATIONS ==========
// Response caching
const responseCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes cache

// Cache middleware
function cacheMiddleware(ttl = CACHE_TTL) {
    return (req, res, next) => {
        // Only cache GET requests
        if (req.method !== 'GET') {
            return next();
        }
        
        const cacheKey = req.originalUrl || req.url;
        const cached = responseCache.get(cacheKey);
        
        if (cached && (Date.now() - cached.timestamp) < ttl) {
            console.log(`⚡ Cache hit: ${cacheKey}`);
            return res.json(cached.data);
        }
        
        // Override res.json to cache response
        const originalJson = res.json;
        res.json = function(data) {
            responseCache.set(cacheKey, {
                data: data,
                timestamp: Date.now()
            });
            originalJson.call(this, data);
        };
        
        next();
    };
}

// Clear cache for specific routes
function clearCacheForCategory(category, folderPath = '') {
    const cacheKeys = Array.from(responseCache.keys());
    cacheKeys.forEach(key => {
        if (key.includes(`category=${category}`) && 
            (folderPath === '' || key.includes(`folderPath=${folderPath}`))) {
            responseCache.delete(key);
            console.log(`🗑️  Cleared cache: ${key}`);
        }
    });
}

// ========== FILE UPLOAD CONFIG ==========
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { 
        fileSize: 100 * 1024 * 1024, // 100MB
        fields: 10,
        files: 10
    }
});

// ========== AUTHENTICATION MIDDLEWARE ==========
function verifyAdminToken(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '') || 
                  req.cookies?.adminToken ||
                  req.query.token;

    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Check if token is expired
        if (decoded.exp && Date.now() >= decoded.exp * 1000) {
            return res.status(401).json({ error: 'Token expired' });
        }
        
        req.admin = decoded;
        next();
    } catch (error) {
        console.error('Token verification error:', error.message);
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// Rate limiting for login attempts
const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

function checkRateLimit(ip) {
    const now = Date.now();
    const attempts = loginAttempts.get(ip) || [];
    
    // Clean old attempts
    const recentAttempts = attempts.filter(time => now - time < LOCKOUT_TIME);
    
    if (recentAttempts.length >= MAX_ATTEMPTS) {
        return false; // Locked out
    }
    
    loginAttempts.set(ip, [...recentAttempts, now]);
    return true;
}

// ========== MIDDLEWARE ==========
app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(cookieParser());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ========== PERFORMANCE MONITORING ==========
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        const logLevel = duration > 1000 ? '⚠️ ' : '⏱️';
        console.log(`${logLevel} ${req.method} ${req.originalUrl} - ${res.statusCode} (${duration}ms)`);
    });
    next();
});

// ========== AUTHENTICATION ENDPOINTS ==========

// 1. Initialize admin user (run once)
app.post('/api/admin/init', async (req, res) => {
    const { initKey, password } = req.body;
    
    if (!initKey || initKey !== ADMIN_INIT_KEY) {
        return res.status(401).json({ error: 'Unauthorized initialization' });
    }

    if (!password || password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    try {
        // Hash the password with bcrypt
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Insert or update admin user
        const { data, error } = await supabase
            .from('admin_users')
            .upsert({
                username: 'admin',
                password_hash: hashedPassword,
                last_login: null,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            }, {
                onConflict: 'username'
            })
            .select()
            .single();

        if (error) {
            console.error('Admin init error:', error);
            
            // If table doesn't exist, guide the user
            if (error.message.includes('relation "admin_users" does not exist')) {
                return res.status(500).json({ 
                    error: 'Admin table does not exist. Please run this SQL in Supabase:',
                    sql: `CREATE TABLE admin_users (
                        id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        failed_attempts INTEGER DEFAULT 0,
                        last_login TIMESTAMPTZ,
                        created_at TIMESTAMPTZ DEFAULT NOW(),
                        updated_at TIMESTAMPTZ DEFAULT NOW()
                    );`
                });
            }
            
            return res.status(500).json({ error: 'Failed to create admin user: ' + error.message });
        }

        console.log('✅ Admin user initialized successfully');
        
        res.json({ 
            success: true, 
            message: 'Admin user initialized successfully',
            note: 'Now disable this endpoint in production or change the ADMIN_INIT_KEY',
            password_set: true
        });
    } catch (error) {
        console.error('Init error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// 2. Login endpoint with rate limiting
app.post('/api/admin/login', async (req, res) => {
    const { password } = req.body;
    const clientIp = req.ip || req.connection.remoteAddress;
    
    // Check rate limit
    if (!checkRateLimit(clientIp)) {
        return res.status(429).json({ 
            error: 'Too many login attempts. Please try again later.' 
        });
    }
    
    if (!password || password.trim() === '') {
        return res.status(400).json({ error: 'Password required' });
    }

    try {
        // Get admin credentials from Supabase
        const { data: admin, error } = await supabase
            .from('admin_users')
            .select('*')
            .eq('username', 'admin')
            .single();

        if (error || !admin) {
            console.error('Admin not found:', error?.message);
            // Delay response to prevent timing attacks
            await bcrypt.compare(password, '$2b$10$fakehashforsecuritytimingattackprevention');
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Verify password
        const isValid = await bcrypt.compare(password, admin.password_hash);
        
        if (!isValid) {
            // Update failed login attempt
            await supabase
                .from('admin_users')
                .update({ 
                    failed_attempts: (admin.failed_attempts || 0) + 1,
                    updated_at: new Date().toISOString()
                })
                .eq('username', 'admin');
            
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Create JWT token
        const token = jwt.sign(
            { 
                username: 'admin',
                role: 'admin',
                iat: Math.floor(Date.now() / 1000),
                exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
            },
            JWT_SECRET
        );

        // Update last login
        await supabase
            .from('admin_users')
            .update({ 
                last_login: new Date().toISOString(),
                failed_attempts: 0,
                updated_at: new Date().toISOString()
            })
            .eq('username', 'admin');

        // Clear rate limit for this IP
        loginAttempts.delete(clientIp);

        // Set HttpOnly cookie for web access
        res.cookie('adminToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });

        res.json({
            success: true,
            token: token,
            expiresIn: 24 * 60 * 60 // 24 hours in seconds
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// 3. Verify token (for frontend checking)
app.get('/api/admin/verify', verifyAdminToken, (req, res) => {
    res.json({
        success: true,
        user: req.admin,
        message: 'Token is valid'
    });
});

// 4. Logout endpoint
app.post('/api/admin/logout', (req, res) => {
    // Clear the cookie
    res.clearCookie('adminToken');
    res.json({ 
        success: true, 
        message: 'Logged out successfully' 
    });
});

// 5. Protected admin data endpoint
app.get('/api/admin/data', verifyAdminToken, cacheMiddleware(), async (req, res) => {
    try {
        // Get all files data (admin sees everything)
        const { data: files, error: filesError } = await supabase
            .from('files')
            .select('*')
            .order('upload_date', { ascending: false });

        // Get all folders
        const { data: folders, error: foldersError } = await supabase
            .from('folders')
            .select('*')
            .order('name');

        // Get storage usage stats
        const { data: storageData } = await supabase.storage
            .from('portfolio-files')
            .list();

        if (filesError || foldersError) {
            console.error('Admin data error:', filesError || foldersError);
            return res.status(500).json({ error: 'Database error' });
        }

        // Get counts
        const { count: totalFiles } = await supabase
            .from('files')
            .select('*', { count: 'exact', head: true });

        const { count: totalFolders } = await supabase
            .from('folders')
            .select('*', { count: 'exact', head: true });

        res.json({
            files: files || [],
            folders: folders || [],
            stats: {
                totalFiles: totalFiles || 0,
                totalFolders: totalFolders || 0,
                storageItems: storageData?.length || 0,
                cacheSize: responseCache.size,
                serverTime: new Date().toISOString()
            }
        });

    } catch (error) {
        console.error('Admin data error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ========== PROTECTED ADMIN ENDPOINTS ==========

// 1. Protected upload
app.post('/api/secure/upload', verifyAdminToken, upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const { category = 'projects', folderPath = '' } = req.body;
    const fileName = Date.now() + '-' + req.file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
    
    try {
        const filePath = `${category}/${folderPath ? folderPath + '/' : ''}${fileName}`.replace(/\/\//g, '/');
        
        const { data: storageData, error: storageError } = await supabase.storage
            .from('portfolio-files')
            .upload(filePath, req.file.buffer, {
                contentType: req.file.mimetype,
                upsert: true
            });

        if (storageError) {
            console.error('Supabase Storage error:', storageError);
            return res.status(500).json({ 
                error: 'Storage upload failed: ' + storageError.message 
            });
        }

        console.log('✅ File uploaded to Supabase Storage by admin:', filePath);

        const { data: dbData, error: dbError } = await supabase
            .from('files')
            .insert({
                filename: fileName,
                original_name: req.file.originalname,
                file_type: req.file.mimetype,
                file_size: req.file.size,
                folder_path: folderPath,
                category: category,
                upload_date: new Date().toISOString(),
                uploaded_by: req.admin.username
            })
            .select()
            .single();

        if (dbError) {
            console.error('Supabase Database error:', dbError);
            await supabase.storage.from('portfolio-files').remove([filePath]);
            return res.status(500).json({ 
                error: 'Database error: ' + dbError.message 
            });
        }

        clearCacheForCategory(category, folderPath);
        if (category === 'resume') {
            responseCache.delete('/resume');
        }

        res.json({
            success: true,
            id: dbData.id,
            filename: fileName,
            original_name: req.file.originalname,
            file_type: req.file.mimetype,
            file_size: req.file.size,
            folder_path: folderPath,
            category: category,
            upload_date: dbData.upload_date || new Date().toISOString()
        });

    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ 
            error: 'Server error: ' + error.message
        });
    }
});

// 2. Protected delete file
app.delete('/api/secure/files/:id', verifyAdminToken, async (req, res) => {
    const fileId = req.params.id;

    try {
        const { data: fileInfo, error: fetchError } = await supabase
            .from('files')
            .select('filename, category, folder_path')
            .eq('id', fileId)
            .single();

        if (fetchError || !fileInfo) {
            return res.status(404).json({ error: 'File not found in database' });
        }

        const filePath = `${fileInfo.category}/${fileInfo.folder_path ? fileInfo.folder_path + '/' : ''}${fileInfo.filename}`.replace(/\/\//g, '/');
        
        const { error: storageError } = await supabase.storage
            .from('portfolio-files')
            .remove([filePath]);

        if (storageError) {
            console.error('Supabase Storage delete error:', storageError);
        }

        const { error: dbError } = await supabase
            .from('files')
            .delete()
            .eq('id', fileId);

        if (dbError) {
            console.error('Supabase Database delete error:', dbError);
            return res.status(500).json({ error: 'Database error: ' + dbError.message });
        }

        clearCacheForCategory(fileInfo.category, fileInfo.folder_path);
        if (fileInfo.category === 'resume') {
            responseCache.delete('/resume');
        }

        res.json({ 
            success: true, 
            message: 'File deleted successfully',
            deletedFile: fileInfo.filename,
            deletedBy: req.admin.username
        });

    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ========== EXISTING PUBLIC ENDPOINTS (KEPT FOR COMPATIBILITY) ==========

// 1. Upload file (public but could be protected)
app.post('/upload', upload.single('file'), async (req, res) => {
    // Same as before, but you might want to protect this
    // Currently leaving it public for backward compatibility
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const { category = 'projects', folderPath = '' } = req.body;
    const fileName = Date.now() + '-' + req.file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
    
    try {
        const filePath = `${category}/${folderPath ? folderPath + '/' : ''}${fileName}`.replace(/\/\//g, '/');
        
        const { data: storageData, error: storageError } = await supabase.storage
            .from('portfolio-files')
            .upload(filePath, req.file.buffer, {
                contentType: req.file.mimetype,
                upsert: true
            });

        if (storageError) {
            console.error('Supabase Storage error:', storageError);
            return res.status(500).json({ 
                error: 'Storage upload failed: ' + storageError.message 
            });
        }

        console.log('✅ File uploaded to Supabase Storage:', filePath);

        const { data: dbData, error: dbError } = await supabase
            .from('files')
            .insert({
                filename: fileName,
                original_name: req.file.originalname,
                file_type: req.file.mimetype,
                file_size: req.file.size,
                folder_path: folderPath,
                category: category,
                upload_date: new Date().toISOString()
            })
            .select()
            .single();

        if (dbError) {
            console.error('Supabase Database error:', dbError);
            await supabase.storage.from('portfolio-files').remove([filePath]);
            return res.status(500).json({ 
                error: 'Database error: ' + dbError.message 
            });
        }

        clearCacheForCategory(category, folderPath);
        if (category === 'resume') {
            responseCache.delete('/resume');
        }

        res.json({
            success: true,
            id: dbData.id,
            filename: fileName,
            original_name: req.file.originalname,
            file_type: req.file.mimetype,
            file_size: req.file.size,
            folder_path: folderPath,
            category: category,
            upload_date: dbData.upload_date || new Date().toISOString()
        });

    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ 
            error: 'Server error: ' + error.message
        });
    }
});

// 2. Get files (with caching) - Public
app.get('/files', cacheMiddleware(), async (req, res) => {
    const { category, folderPath = '' } = req.query;

    try {
        const query = supabase
            .from('files')
            .select('*', { count: 'exact' })
            .order('upload_date', { ascending: false })
            .limit(100);

        if (category) {
            query.eq('category', category);
        }

        if (folderPath !== undefined && folderPath !== '') {
            query.eq('folder_path', folderPath);
        }

        const { data: files, error, count } = await query;

        if (error) {
            console.error('Supabase query error:', error);
            return res.status(500).json({ error: 'Database error: ' + error.message });
        }

        const response = {
            files: files || [],
            metadata: {
                count: count || 0,
                timestamp: new Date().toISOString(),
                cached: false
            }
        };

        res.json(response.files);

    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// 3. Get resume (optimized with caching) - Public
app.get('/resume', cacheMiddleware(2 * 60 * 1000), async (req, res) => {
    try {
        const { data: resumes, error } = await supabase
            .from('files')
            .select('*')
            .eq('category', 'resume')
            .order('upload_date', { ascending: false })
            .limit(1);

        if (error) {
            console.error('Supabase error:', error);
            return res.status(500).json({ error: 'Database error: ' + error.message });
        }

        if (resumes && resumes.length > 0) {
            res.json(resumes[0]);
        } else {
            res.json({});
        }
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// 4. Download file (optimized) - Public
app.get('/files/:filename', async (req, res) => {
    const filename = req.params.filename;
    
    try {
        const fileInfoPromise = supabase
            .from('files')
            .select('category, folder_path, original_name')
            .eq('filename', filename)
            .single();

        const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Database query timeout')), 5000)
        );

        const { data: fileInfo, error: dbError } = await Promise.race([
            fileInfoPromise,
            timeoutPromise
        ]);

        if (dbError || !fileInfo) {
            return res.status(404).json({ error: 'File not found in database' });
        }

        const filePath = `${fileInfo.category}/${fileInfo.folder_path ? fileInfo.folder_path + '/' : ''}${filename}`.replace(/\/\//g, '/');
        
        const { data: urlData } = supabase.storage
            .from('portfolio-files')
            .getPublicUrl(filePath);

        res.setHeader('Cache-Control', 'public, max-age=3600');
        res.setHeader('X-Accel-Redirect', urlData.publicUrl);
        
        // FIXED: Use SUPABASE_URL variable instead of hardcoded URL
        const directUrl = `${SUPABASE_URL}/storage/v1/object/public/portfolio-files/${fileInfo.category}/${fileInfo.folder_path ? fileInfo.folder_path + '/' : ''}${filename}`.replace(/\/\//g, '/');
        
        res.redirect(301, directUrl);

    } catch (error) {
        console.error('Download error:', error);
        
        if (error.message === 'Database query timeout') {
            console.log('⚠️ Database timeout, trying direct URL');
            // FIXED: Use SUPABASE_URL variable instead of hardcoded URL
            const directUrl = `${SUPABASE_URL}/storage/v1/object/public/portfolio-files/resume/${filename}`;
            res.redirect(301, directUrl);
        } else {
            res.status(500).json({ error: 'File download failed: ' + error.message });
        }
    }
});

// 5. Delete file - Consider protecting this
app.delete('/files/:id', async (req, res) => {
    const fileId = req.params.id;

    try {
        const { data: fileInfo, error: fetchError } = await supabase
            .from('files')
            .select('filename, category, folder_path')
            .eq('id', fileId)
            .single();

        if (fetchError || !fileInfo) {
            return res.status(404).json({ error: 'File not found in database' });
        }

        const filePath = `${fileInfo.category}/${fileInfo.folder_path ? fileInfo.folder_path + '/' : ''}${fileInfo.filename}`.replace(/\/\//g, '/');
        
        const { error: storageError } = await supabase.storage
            .from('portfolio-files')
            .remove([filePath]);

        if (storageError) {
            console.error('Supabase Storage delete error:', storageError);
        }

        const { error: dbError } = await supabase
            .from('files')
            .delete()
            .eq('id', fileId);

        if (dbError) {
            console.error('Supabase Database delete error:', dbError);
            return res.status(500).json({ error: 'Database error: ' + dbError.message });
        }

        clearCacheForCategory(fileInfo.category, fileInfo.folder_path);
        if (fileInfo.category === 'resume') {
            responseCache.delete('/resume');
        }

        res.json({ 
            success: true, 
            message: 'File deleted successfully',
            deletedFile: fileInfo.filename
        });

    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// 6. Create folder - Consider protecting this
app.post('/folders', async (req, res) => {
    const { name, category, parentPath = '' } = req.body;

    if (!name || !category) {
        return res.status(400).json({ error: 'Missing required fields: name and category' });
    }

    try {
        const { data: folder, error } = await supabase
            .from('folders')
            .insert({
                name: name.trim(),
                parent_path: parentPath,
                category: category
            })
            .select()
            .single();

        if (error) {
            console.error('Supabase error:', error);
            return res.status(500).json({ error: 'Database error: ' + error.message });
        }

        clearCacheForCategory(category, parentPath);

        res.json({
            success: true,
            folder: folder
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// 7. Get folders (with caching) - Public
app.get('/folders', cacheMiddleware(), async (req, res) => {
    const { category, parentPath = '' } = req.query;

    try {
        const { data: folders, error } = await supabase
            .from('folders')
            .select('*')
            .eq('category', category)
            .eq('parent_path', parentPath)
            .order('name');

        if (error) {
            console.error('Supabase error:', error);
            return res.status(500).json({ error: 'Database error: ' + error.message });
        }

        res.json(folders || []);
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// 8. Delete folder - Consider protecting this
app.delete('/folders/:id', async (req, res) => {
    const folderId = req.params.id;

    try {
        const { data: folder, error: fetchError } = await supabase
            .from('folders')
            .select('*')
            .eq('id', folderId)
            .single();

        if (fetchError || !folder) {
            return res.status(404).json({ error: 'Folder not found' });
        }

        const fullFolderPath = folder.parent_path ? 
            `${folder.parent_path}/${folder.name}` : folder.name;

        const { data: files, error: filesError } = await supabase
            .from('files')
            .select('filename')
            .eq('category', folder.category)
            .eq('folder_path', fullFolderPath);

        if (!filesError && files && files.length > 0) {
            const filePaths = files.map(file => 
                `${folder.category}/${fullFolderPath ? fullFolderPath + '/' : ''}${file.filename}`.replace(/\/\//g, '/')
            );
            
            await Promise.allSettled([
                supabase.storage.from('portfolio-files').remove(filePaths),
                supabase.from('files')
                    .delete()
                    .eq('category', folder.category)
                    .eq('folder_path', fullFolderPath)
            ]);
        }

        await Promise.allSettled([
            supabase.from('folders').delete().eq('parent_path', fullFolderPath),
            supabase.from('folders').delete().eq('id', folderId)
        ]);

        clearCacheForCategory(folder.category);

        res.json({ 
            success: true,
            message: 'Folder and all contents deleted successfully'
        });

    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// 9. Health check endpoint (optimized)
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        environment: isVercel ? 'Vercel' : 'Local',
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        cacheSize: responseCache.size,
        authEnabled: true
    });
});

// 10. Cache management endpoint - Protected
app.get('/cache/clear', verifyAdminToken, (req, res) => {
    const { category } = req.query;
    
    if (category) {
        clearCacheForCategory(category);
        res.json({ success: true, message: `Cache cleared for ${category}` });
    } else {
        responseCache.clear();
        res.json({ success: true, message: 'All cache cleared' });
    }
});

// ========== ERROR HANDLING ==========
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({ error: 'File too large. Maximum size is 100MB.' });
        }
    }
    
    res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'production' ? 'Something went wrong' : err.message 
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// ========== START SERVER ==========
if (require.main === module) {
    const server = app.listen(PORT, () => {
        console.log('='.repeat(50));
        console.log('🚀 PORTFOLIO SERVER STARTED!');
        console.log('='.repeat(50));
        console.log(`📍 Local: http://localhost:${PORT}`);
        console.log(`📍 Login: http://localhost:${PORT}/`);
        console.log(`📍 Admin: http://localhost:${PORT}/admin (protected)`);
        console.log(`📍 Public: http://localhost:${PORT}/public`);
        console.log(`☁️  Environment: ${isVercel ? 'Vercel' : 'Local'}`);
        console.log(`🔐 Authentication: ${JWT_SECRET !== 'your-fallback-secret-change-in-production' ? 'Enabled' : '⚠️ Using default secret'}`);
        console.log(`📦 Storage: Supabase (portfolio-files)`);
        console.log(`🗄️  Database: Supabase PostgreSQL`);
        console.log(`⚡ Performance: Caching enabled (${CACHE_TTL/1000}s TTL)`);
        console.log('='.repeat(50));
        console.log('📋 Available endpoints:');
        console.log('  POST /api/admin/login    - Admin login');
        console.log('  POST /api/admin/init     - Initialize admin (run once)');
        console.log('  GET  /api/admin/verify   - Verify token');
        console.log('  GET  /api/admin/data     - Admin data (protected)');
        console.log('  POST /api/secure/upload  - Protected upload');
        console.log('='.repeat(50));
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
        console.log('SIGTERM received. Shutting down gracefully...');
        server.close(() => {
            console.log('Server closed.');
            process.exit(0);
        });
    });
}

// Export for Vercel
module.exports = app;
