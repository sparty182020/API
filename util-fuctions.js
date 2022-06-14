/**
 * 
 * @param {String} message 
 * @param {{}=} previous_data 
 * @returns {{status: String, reason: String, received: Boolean}}
 */
function failedStatus(message,previous_data) {
    const startingData = {
        status: 'failed',
        reason: `${message}`,
        received: true,
    }
    const addedData = previous_data || {};
    const string = `${JSON.stringify(startingData)}${JSON.stringify(addedData)}`
    const fixed = string.replace(/(\}\{)/gmi,',')
    const fixedArray = JSON.parse(fixed)
    return fixedArray
}

module.exports = {
    failedStatus
}