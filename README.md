# 1. Title: Songgestions

## 2. What is it?
Our team at BBY06 is developing an AI-powered music recommendation app to help music listeners find new songs to listen to based on their unique tastes.

## 3. Technologies Used: 
* Frontend: EJS/HTML/CSS
* Backend: Node.js
* Database: MongoDB
* Other Tools: axios, bcrypt, joi, express, crypto

## 4. Listing of File Contents of Folder:

Contents of the project folder:

```
Project Directory:
|   .env
|   .gitignore
|   databaseConnection.js
|   index.js
|   package-lock.json
|   package.json
|   passwords.txt
|   Procfile
|   README.md
|   Tree.txt
|   utils.js
|   
+---public
|   +---img
|   |       AdobeStock_223605406_Preview.jpeg
|   |       android-chrome-192x192.png
|   |       android-chrome-512x512.png
|   |       apple-touch-icon.png
|   |       band_music.jpg
|   |       fave.jpg
|   |       favicon-16x16.png
|   |       favicon-32x32.png
|   |       favicon.ico
|   |       home.png
|   |       love.jpg
|   |       Musical-note.png
|   |       musical.png
|   |       notes.jpg
|   |       phone_guy.jpg
|   |       placeholder-pfp.jpg
|   |       playlist.png
|   |       playlists.jpg
|   |       record.avif
|   |       rickroll.gif
|   |       search.png
|   |       sfx.jpg
|   |       site.webmanifest
|   |       Songgestions_logo.png
|   |       star.png
|   |       trace.svg
|   |       wave.jpg
|   |       
|   \---sounds
|           jump.mp3
|           rickroll.mp3
|           
+---scripts
|       likesDislikes.js
|       
\---views
    |   404.ejs
    |   about.ejs
    |   admin.ejs
    |   contact.ejs
    |   createUser.ejs
    |   dataHistory.ejs
    |   errorMessage.ejs
    |   favourites.ejs
    |   filters.ejs
    |   forgotPassword.ejs
    |   history.ejs
    |   index.ejs
    |   loggedin.ejs
    |   login.ejs
    |   playlists.ejs
    |   profile.ejs
    |   profileUser.ejs
    |   recommendations.ejs
    |   recommendationsTuning.ejs
    |   resetPassword.ejs
    |   resetPasswordError.ejs
    |   results.ejs
    |   search.ejs
    |   securityQuestion.ejs
    |   securityQuestionError.ejs
    |   submitEmail.ejs
    |   tokenExpired.ejs
    |   userSettings.ejs
    |     
    \---templates
            footer.ejs
            header.ejs
            user.ejs
```    

## 5. Installation and Usage of the project

To set up the development environment and run the project locally, follow these steps:

(Pleae note the installation of the [Songgestion Engine](https://github.com/Tarasios/SonggestionsEngine) on localhost is required for both options.)

* Option 1: 
http://pqrhigvnxy.eu09.qoddiapp.com/ Search for a song and click the "Recommendations" button to receive a recommendation.

* Option 2: 
Localhost Clone the repository:git clone https://github.com/PhoenixAlpha204/2800-202310-BBY06 Install the required dependencies: npm install run node: node index.js Access via your localhost. Search for a song and click the "Songgest" button to receive a recommendation.

## 6. How to use the product (Features):

To register for Songgestions, new users are required to provide their username, email, password, and select a security question. Once the account creation form is fully filled out and submitted, users will be directed to the landing page exclusively for logged-in users. A welcome message will greet them and display their username at the top of the page.

To begin receiving personalized recommendations, simply click on the "Recommendations" option in the Navbar or use the blue "Songgest" button located on the landing page. You will be presented with a vertical stack of cards, showcasing five songs. Each card will display the song's name along with interactive buttons such as "Add to Favorites," "Like/Dislike," and "Songgest Me." Additionally, an embedded Spotify player will allow you to preview a sample of each song. To discover new songs, simply refresh the page.

To search songs, simply click on the "Browse" option in the navbar. Enter the name of a song, and a list of songs will be presented to you in a vertical stack of cards. Given the extensive database, locating a specific song may require some additional steps. To streamline your search, click on the blue "Filter" button located at the bottom right corner. This will enable users to refine their search further by specifying the artist or album name, ensuring more accurate and targeted results.

To utilize the AI-powered "Songgest Me" feature, simply click the "Songgest Me" button once you have found a song. For optimal results, please ensure that the Songgestion Engine is operational. Instructions on how to set it up can be found here: [Link to Songgestion Engine's GitHub page](https://github.com/Tarasios/SonggestionsEngine).

## 7. Credits, References, and Licenses:

**Spotify API**

The Spotify API has been utilized in this app to provide music-related features. The integration of the Spotify API, allows users to quickly listen to a preview of songs, retrieve and display music 

**Adobe Stock**

Certain stock images on our site have been sourced from Adobe Stock. These visual resources have contributed to the aesthetic appeal and design of our app.

**Kaggle Dataset**

The Kaggle dataset used in this project is sourced from https://www.kaggle.com/datasets/salvatorerastelli/spotify-and-youtube


## 8. AI Usage:

In Songgestions, we utilized Machine Learning to power our song recommendation system. Here's how AI was used:

ChatGPT, an AI language model, assisted us in creating a roadmap for our project and guiding us through certain decision points.
We built our own TensorFlow model for song recommendations using a Kaggle dataset.
AI was not used, however, in the creation of the dataset. Only in using it.
As the web server hosting limitations prevent us from running the Python API server-side, the TensorFlow model needs to be downloaded and run client-side.

## 9. Contact Information:

**Connie Gildemeister**
   
    Discord: Connie Allure~#1510

**Cassiel Williams (Tarasios)**

    Discord: Tarasios#9030

**Quincy Wong**

    Discord: PhoenixAlpha#0740

**Vincent Cheung**

    Discord: Vyttmin#6355

Please feel free to reach out to any of us through Discord for any questions, collaborations, or general inquiries. We look forward to hearing from you!
