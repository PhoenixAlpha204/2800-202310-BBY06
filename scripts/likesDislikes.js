function liked(array, id) {
    if (array.likes.includes(id)) {
        return "blue";
    } else {
        return "black";
    }
};

function disliked(array, id) {
    if (array.dislikes.includes(id)) {
        return "blue";
    } else {
        return "black";
    }
};

function favourited(array, id) {
    if (array.favourites.includes(id)) {
        return "gold";
    } else {
        return "black";
    }
};

module.exports = {
    liked: liked,
    disliked: disliked,
    favourited: favourited,
}
