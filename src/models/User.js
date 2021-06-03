const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        unique: true,
        required: true
    },
    password: {
        type: String,
        required: true
    }
});

userSchema.pre('save', function (next) {
    const user = this;
    if (!user.isModified('password')) {
        return next();
    }

    bcrypt.genSalt(10, (err, salt) => {
        if (err) {
            return next(err);
        }

        bcrypt.hash(user.password, salt, (err, hash) => {
            if (err){
                return next(err);
            } 
            user.password = hash;
            next();
        });
    });
});

//candidatePassword is the password entered by the user in the future login.
userSchema.methods.comparePassword = function(candidatePassword) {
    const user = this;
    return new Promise((resolve, reject) => {
        // here we are comparing the password against the already stored and hashed password in the databse.
        bcrypt.compare(candidatePassword, user.password, (err, isMatch) => {
            if (err){
                return reject(err);
            }

            if(!isMatch){
                return reject(false);
            }

            resolve(true);
        });
    });
}

mongoose.model('User', userSchema);