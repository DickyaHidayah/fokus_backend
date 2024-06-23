const db = require('../config/db');

exports.createOrganization = (req, res) => {
    const {
        representative_name, email, phone, password, organization_name, founded_date, description, logo,
        location, organization_email, organization_phone, website
    } = req.body;

    // Hash password
    const hashedPassword = bcrypt.hashSync(password, 10);

    const user = {
        name: representative_name,
        email,
        password: hashedPassword,
        phone,
        role: 'organization'
    };

    db.query('INSERT INTO Users SET ?', user, (err, result) => {
        if (err) throw err;

        const organization = {
            user_id: result.insertId,
            representative_name,
            organization_name,
            organization_email,
            organization_phone,
            founded_date,
            description,
            logo,
            location,
            website
        };

        db.query('INSERT INTO Organizations SET ?', organization, (err, result) => {
            if (err) throw err;
            res.status(201).json({ message: 'Organization registered!' });
        });
    });
};

exports.getOrganizations = (req, res) => {
    db.query('SELECT * FROM Organizations', (err, results) => {
        if (err) throw err;
        res.status(200).json(results);
    });
};

exports.getOrganizationById = (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM Organizations WHERE id = ?', [id], (err, result) => {
        if (err) throw err;
        res.status(200).json(result);
    });
};

exports.updateOrganization = (req, res) => {
    const { id } = req.params;
    const updateData = req.body;

    db.query('UPDATE Organizations SET ? WHERE id = ?', [updateData, id], (err, result) => {
        if (err) throw err;
        res.status(200).json({ message: 'Organization updated!' });
    });
};

exports.deleteOrganization = (req, res) => {
    const { id } = req.params;

    db.query('DELETE FROM Organizations WHERE id = ?', [id], (err, result) => {
        if (err) throw err;
        res.status(200).json({ message: 'Organization deleted!' });
    });
};
