require('dotenv').config();
const express = require('express');
const cors = require('cors');
const app = express();
app.options('*', cors());
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS','PATCH'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json());
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date() }));

const { createClient } = require('@supabase/supabase-js');
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, supabaseServiceRoleKey);

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const auth = require('./middleware/auth');

app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await supabase.from('expense_tracker_expense_tracker_users').insert([{
            email,
            password: hashedPassword,
            name
        }]);
        const token = jwt.sign({ userId: user.data[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await supabase.from('expense_tracker_expense_tracker_users').select('*').eq('email', email);
        if (!user.data.length) {
            return res.status(404).json({ error: 'User not found' });
        }
        const isValidPassword = await bcrypt.compare(password, user.data[0].password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Invalid password' });
        }
        const token = jwt.sign({ userId: user.data[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/api/auth/me', auth.verifyToken, async (req, res) => {
    try {
        const user = await supabase.from('expense_tracker_expense_tracker_users').select('*').eq('id', req.userId);
        res.json(user.data[0]);
    } catch (error) {
        res.status(404).json({ error: error.message });
    }
});

app.post('/api/expenses', auth.verifyToken, async (req, res) => {
    try {
        const { title, amount, category } = req.body;
        const expense = await supabase.from('expense_tracker_expense_tracker_expenses').insert([{
            title,
            amount,
            category,
            user_id: req.userId
        }]);
        res.json(expense.data[0]);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/api/expenses', auth.verifyToken, async (req, res) => {
    try {
        const expenses = await supabase.from('expense_tracker_expense_tracker_expenses').select('*').eq('user_id', req.userId);
        res.json(expenses.data);
    } catch (error) {
        res.status(404).json({ error: error.message });
    }
});

app.get('/api/expenses/summary', auth.verifyToken, async (req, res) => {
    try {
        const expenses = await supabase.from('expense_tracker_expense_tracker_expenses').select('amount').eq('user_id', req.userId);
        const total = expenses.data.reduce((acc, curr) => acc + parseFloat(curr.amount), 0);
        res.json({ total });
    } catch (error) {
        res.status(404).json({ error: error.message });
    }
});

app.delete('/api/expenses/:id', auth.verifyToken, async (req, res) => {
    try {
        const id = req.params.id;
        await supabase.from('expense_tracker_expense_tracker_expenses').delete().eq('id', id).eq('user_id', req.userId);
        res.json({ message: 'Expense deleted successfully' });
    } catch (error) {
        res.status(404).json({ error: error.message });
    }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server started on port ${port}`));