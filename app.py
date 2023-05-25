from flask import Flask, jsonify
import pandas as pd
import tensorflow as tf

# Import the necessary functions from process.py
from process import load_songs, preprocess_text, build_song_model, define_task, create_retrieval_model, \
    setup_retrieval_model, get_song_recommendations

app = Flask(__name__)

# Load the data and initialize the model
songs = load_songs()
songs = preprocess_text(songs)
song_model = build_song_model()
task = define_task(songs, song_model)
model = create_retrieval_model(song_model, task)
index = setup_retrieval_model(model, songs)
# Load the data into the 'data' DataFrame
data = pd.read_csv('Untrimmeddata.csv')
try:
    saved_model = tf.keras.models.load_model('content_based_model.h5')
except OSError as e:
    print(f"Failed to load the model: {e}")

# Define a route for the root URL
@app.route('/')
def hello():
    return "Hello, Flask!"


@app.route('/recommend/<int:song_id>')
def recommend_song(song_id):
    track = data[data['id'] == song_id]['Track'].values[0]  # Retrieve the associated track
    recommendations, urls = get_song_recommendations(index, song_id, data)

    response = {
        'Given Song ID': song_id,
        'Given song name': track,
        'recommendations': recommendations.tolist(),
        'urls': urls
    }
    return jsonify(response)


if __name__ == '__main__':
    app.run()
