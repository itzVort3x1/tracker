require('./models/User');
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/authRoutes');

const app = express();

app.use(bodyParser.json());
app.use(authRoutes);

const mongoUri = 'mongodb://localhost/track_server';

mongoose.connect(mongoUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true
});
mongoose.connection.on('connected', () => {
    console.log("Connected to mongo instance");
});
mongoose.connection.on('error', (err) => {
    console.log('Error connecting to mongo', err);
})

app.get('/', (req, res) => {
    res.send("Hello");
});

app.listen(3000, () => {
    console.log("Listening on port 3000");
})