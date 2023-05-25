import tensorflow as tf
import tensorflow_datasets as tfds
import tensorflow_recommenders as tfrs
import pandas as pd
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

vocab_size = 10000  # Define the vocabulary size
embedding_dim = 100  # Define the embedding dimension
max_length = 1  # Define the maximum length of input sequences
num_classes = 10  # Define the number of classes

# Function to load song data
def load_songs():
    data = pd.read_csv('Untrimmeddata.csv')
    songs = data['Title'].astype(str).values
    return songs

# Function to preprocess and tokenize the song titles
def preprocess_text(texts):
    tokenizer = Tokenizer(num_words=vocab_size, oov_token="<OOV>")
    tokenizer.fit_on_texts(texts)
    sequences = tokenizer.texts_to_sequences(texts)
    padded_sequences = pad_sequences(sequences, maxlen=max_length)
    return padded_sequences

# Function to build song model
def build_song_model():
    song_model = tf.keras.Sequential()
    song_model.add(tf.keras.layers.Embedding(input_dim=vocab_size, output_dim=embedding_dim, input_length=max_length))
    song_model.add(tf.keras.layers.Flatten())
    song_model.add(tf.keras.layers.Dense(64, activation='relu'))
    song_model.add(tf.keras.layers.Dense(5000, activation='softmax'))
    return song_model

# Function to define the task
def define_task(songs, song_model):
    class Task(tfrs.tasks.Retrieval):
        def __init__(self, songs, song_model):
            super().__init__()
            self.songs = songs
            self.song_model = song_model

        def compute_loss(self, features, training=False):
            song_embeddings = self.song_model(features["title"])  # Pass only the "title" feature
            return self.query(song_embeddings, compute_metrics=not training)

    task = Task(songs, song_model)
    return task

# Function to create the retrieval model
def create_retrieval_model(song_model, task):
    class SpotifyModel(tfrs.Model):
        def __init__(self, song_model, task):
            super().__init__()
            self.song_model = song_model
            self.task = task

        def compute_loss(self, features, training=False):
            song_embeddings = self.song_model(features)
            return self.task(song_embeddings, song_embeddings)

    model = SpotifyModel(song_model, task)
    model.compile(optimizer=tf.keras.optimizers.Adagrad(0.5))
    return model

# Function to train the model
def train_model(model, songs):
    dataset = tf.data.Dataset.from_tensor_slices(songs)
    model.fit(dataset.batch(4096), epochs=3)

# Function to set up retrieval using trained representations
def setup_retrieval_model(model, songs):
    index = tfrs.layers.factorized_top_k.BruteForce(model.song_model)
    song_embeddings = model.song_model.predict(songs)  # Generate embeddings outside tf.function
    index.index_from_dataset(tf.data.Dataset.from_tensor_slices((songs, song_embeddings)).batch(100))
    return index

# Function to get song recommendations
def get_song_recommendations(index, song_id, data):
    song_id = [[song_id]]  # Wrap the song_id in a list to create a list of sequences
    song_id = pad_sequences(song_id, maxlen=max_length)
    _, song_indices = index(song_id)
    top_song_index = song_indices[0, 0]  # Get the index of the top recommended song
    song_title = data.iloc[top_song_index]['Track']  # Retrieve the song title from the data
    uri_series = data.iloc[top_song_index]['Uri']  # Retrieve the Uri series from the data

    spotify_links = []
    for uri in uri_series:
        uri_parts = uri.split(":")
        track_id = uri_parts[-1]
        spotify_link = f"https://open.spotify.com/track/{track_id}"
        spotify_links.append(spotify_link)

    return song_title, spotify_links

# Main function to run the program
def main():
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
        return

    song_id = 9126  # Enter the song ID for which you want recommendations
    recommendations, urls = get_song_recommendations(index, song_id, data)  # Pass 'data' to the function
    track = data[data['id'] == song_id]['Track'].values[0]  # Retrieve the associated track
    print("Recommended songs for", track, ":")
    for recommendation, url in zip(recommendations, urls):
        print(recommendation)
        print("Spotify URL:", url)

if __name__ == "__main__":
    main()
