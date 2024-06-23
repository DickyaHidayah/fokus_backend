const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../config/db');

exports.register = async (req, res) => {
    const { name, email, password, phone, role } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const user = { name, email, password: hashedPassword, phone, role };
        const query = 'INSERT INTO Users SET ?';
        
        db.query(query, user, (err, result) => {
            if (err) throw err;
            res.status(201).json({ message: 'User registered!' });
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.login = (req, res) => {
    const { email, password } = req.body;

    const query = 'SELECT * FROM Users WHERE email = ?';

    db.query(query, [email], async (err, results) => {
        if (err) throw err;

        if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const user = results[0];

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, {
            expiresIn: '1h'
        });

        res.status(200).json({ token });
    });
};
