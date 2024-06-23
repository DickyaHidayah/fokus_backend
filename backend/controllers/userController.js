const db = require('../config/db');

exports.getUser = (req, res) => {
    const { id } = req.user;

    db.query('SELECT * FROM Users WHERE id = ?', [id], (err, result) => {
        if (err) throw err;
        res.status(200).json(result);
    });
};

exports.updateUser = (req, res) => {
    const { id } = req.user;
    const updateData = req.body;

    db.query('UPDATE Users SET ? WHERE id = ?', [updateData, id], (err, result) => {
        if (err) throw err;
        res.status(200).json({ message: 'User updated!' });
    });
};

exports.deleteUser = (req, res) => {
    const { id } = req.user;

    db.query('DELETE FROM Users WHERE id = ?', [id], (err, result) => {
        if (err) throw err;
        res.status(200).json({ message: 'User deleted!' });
    });
};
