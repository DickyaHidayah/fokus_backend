const db = require('../config/db');

exports.createProject = (req, res) => {
    const {
        organization_id, name, description, requirements, location, start_date, end_date, working_hours,
        volunteers_needed, background_image
    } = req.body;

    const project = {
        organization_id,
        name,
        description,
        requirements,
        location,
        start_date,
        end_date,
        working_hours,
        volunteers_needed,
        background_image
    };

    db.query('INSERT INTO Projects SET ?', project, (err, result) => {
        if (err) throw err;
        res.status(201).json({ message: 'Project created!' });
    });
};

exports.getProjects = (req, res) => {
    db.query('SELECT * FROM Projects', (err, results) => {
        if (err) throw err;
        res.status(200).json(results);
    });
};

exports.getProjectById = (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM Projects WHERE id = ?', [id], (err, result) => {
        if (err) throw err;
        res.status(200).json(result);
    });
};

exports.updateProject = (req, res) => {
    const { id } = req.params;
    const updateData = req.body;

    db.query('UPDATE Projects SET ? WHERE id = ?', [updateData, id], (err, result) => {
        if (err) throw err;
        res.status(200).json({ message: 'Project updated!' });
    });
};

exports.deleteProject = (req, res) => {
    const { id } = req.params;

    db.query('DELETE FROM Projects WHERE id = ?', [id], (err, result) => {
        if (err) throw err;
        res.status(200).json({ message: 'Project deleted!' });
    });
};
