const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;

// Supabase is optional — if not configured, fall back to in-memory only
let supabase = null;
if (supabaseUrl && supabaseKey) {
    supabase = createClient(supabaseUrl, supabaseKey);
    console.log('Supabase connected');
} else {
    console.log('Supabase not configured — running in-memory only (data will not persist across restarts)');
}

// ── USER FUNCTIONS ──

async function getUser(username) {
    if (!supabase) return null;
    const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('username', username)
        .single();
    if (error || !data) return null;
    return {
        username: data.username,
        passwordHash: data.password_hash,
        usernameChanged: data.username_changed,
        settings: data.settings
    };
}

async function createUser(username, passwordHash, settings) {
    if (!supabase) return;
    const { error } = await supabase
        .from('users')
        .insert({
            username,
            password_hash: passwordHash,
            username_changed: false,
            settings: settings || { notifications: true, autoConfirm: false, haptic: true }
        });
    if (error) throw error;
}

async function updateUser(username, fields) {
    if (!supabase) return;
    const update = {};
    if (fields.passwordHash !== undefined) update.password_hash = fields.passwordHash;
    if (fields.usernameChanged !== undefined) update.username_changed = fields.usernameChanged;
    if (fields.settings !== undefined) update.settings = fields.settings;
    const { error } = await supabase
        .from('users')
        .update(update)
        .eq('username', username);
    if (error) throw error;
}

async function deleteUser(username) {
    if (!supabase) return;
    const { error } = await supabase
        .from('users')
        .delete()
        .eq('username', username);
    if (error) throw error;
}

async function userExists(username) {
    if (!supabase) return false;
    const { data } = await supabase
        .from('users')
        .select('username')
        .eq('username', username)
        .single();
    return !!data;
}

async function renameUser(oldUsername, newUsername, extraFields) {
    if (!supabase) return;
    const update = { username: newUsername };
    if (extraFields) {
        if (extraFields.usernameChanged !== undefined) update.username_changed = extraFields.usernameChanged;
    }
    const { error } = await supabase
        .from('users')
        .update(update)
        .eq('username', oldUsername);
    if (error) throw error;
    // Sessions cascade via ON UPDATE CASCADE
}

// ── SESSION FUNCTIONS ──

async function createSession(token, username) {
    if (!supabase) return;
    const { error } = await supabase
        .from('sessions')
        .insert({ token, username });
    if (error) throw error;
}

async function getSession(token) {
    if (!supabase) return null;
    const { data, error } = await supabase
        .from('sessions')
        .select('username')
        .eq('token', token)
        .single();
    if (error || !data) return null;
    return data;
}

async function deleteSession(token) {
    if (!supabase) return;
    const { error } = await supabase
        .from('sessions')
        .delete()
        .eq('token', token);
    if (error) throw error;
}

async function deleteSessionsByUsername(username) {
    if (!supabase) return;
    const { error } = await supabase
        .from('sessions')
        .delete()
        .eq('username', username);
    if (error) throw error;
}

// ── ROOM FUNCTIONS ──

async function saveRoom(code, roomData) {
    if (!supabase) return;
    const { error } = await supabase
        .from('rooms')
        .upsert({
            code,
            room_data: roomData,
            last_activity: new Date().toISOString()
        }, { onConflict: 'code' });
    if (error) throw error;
}

async function deleteRoom(code) {
    if (!supabase) return;
    const { error } = await supabase
        .from('rooms')
        .delete()
        .eq('code', code);
    if (error) throw error;
}

async function getAllRooms() {
    if (!supabase) return [];
    const { data, error } = await supabase
        .from('rooms')
        .select('code, room_data');
    if (error) throw error;
    return data || [];
}

module.exports = {
    getUser,
    createUser,
    updateUser,
    deleteUser,
    userExists,
    renameUser,
    createSession,
    getSession,
    deleteSession,
    deleteSessionsByUsername,
    saveRoom,
    deleteRoom,
    getAllRooms
};
