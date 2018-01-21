const path = require('path');

module.exports = {
  entry: [
    "openpgp",
    "whatwg-fetch",
    "promise-polyfill",
  ],

  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'public'),
  },
};
