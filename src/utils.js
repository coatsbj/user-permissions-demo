Array.isEmpty = (arr) => !(Array.isArray(arr) && arr.length);

Array.prototype.contains = function _contains(val) {
    return this.indexOf(val) !== -1;
};