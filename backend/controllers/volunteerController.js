const db = require('../config/db');

exports.createVolunteerProfile = (req, res) => {
    const { user_id, bio, skills, address, city, state, country, zip_code, profile_picture } = req.body;

    const volunteer = {
        user_id,
        bio,
        skills,
        address,
        city,
        state,
        country,
        zip_code,
        profile_picture
    };

    db.query('INSERT INTO Volunteers SET ?', volunteer, (err, result) => {
        if (err) throw err;
        res.status(201).json({ message: 'Volunteer profile created!' });
    });
};

exports.getVolunteers = (req, res) => {
    db.query('SELECT * FROM Volunteers', (err, results) => {
        if (err) throw err;
        res.status(200).json(results);
    });
};

exports.getVolunteerById = (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM Volunteers WHERE id = ?', [id], (err, result) => {
        if (err) throw err;
        res.status(200).json(result);
    });
};

exports.updateVolunteerProfile = (req, res) => {
    const { id } = req.params;
    const updateData = req.body;

    db.query('UPDATE Volunteers SET ? WHERE id = ?', [updateData, id], (err, result) => {
        if (err) throw err;
        res.status(200).json({ message: 'Volunteer profile updated!' });
    });
};

exports.deleteVolunteerProfile = (req, res) => {
    const { id } = req.params;

    db.query('DELETE FROM Volunteers WHERE id = ?', [id], (err, result) => {
        if (err) throw err;
        res.status(200).json({ message: 'Volunteer profile deleted!' });
    });
};
