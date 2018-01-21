const path = require('path');

module.exports = {
  entry: [
    path.resolve(__dirname, 'rc_openpgpjs.js'),
  ],

  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'public'),
  },
};
