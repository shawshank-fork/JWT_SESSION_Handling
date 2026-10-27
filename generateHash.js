const bcrypt = require("bcryptjs");

async function generateHash() {
    const plainPassword = "password";

    const passwordHash = await bcrypt.hash(plainPassword, 12);

    console.log(passwordHash);
}

generateHash();