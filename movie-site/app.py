from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt
import datetime
import re
from better_profanity import profanity      # THIS HAS A 67% CHANCE OF WORKING (SOMETIMES IT DOESN'T WORK FOR SOME REASON)

profanity.load_censor_words()

app = Flask(__name__)
app.secret_key = "frames-secret-key"

DB_PATH = "PWAFramesDatabase.db"

# DATABASE PROGRAM FROM PREVIOUS USERREGISTRATION.PY FILE + MODIFICATIONS SUCH AS FLASK INTEGRATION. 

def get_db():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS AccountsDetail (
        UserID INTEGER PRIMARY KEY AUTOINCREMENT,
        Username TEXT UNIQUE NOT NULL,
        UserPassword TEXT NOT NULL,
        UserEmail TEXT UNIQUE NOT NULL,
        UserPFP TEXT,
        UserJoinDate TEXT,
        UserReviewCount INTEGER DEFAULT 0,
        UserTitle TEXT,
        UserDescription TEXT,
        UserAuthorityLevel INTEGER DEFAULT 1
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS MovieList (
        FilmID INTEGER PRIMARY KEY AUTOINCREMENT,
        FilmName TEXT NOT NULL,
        FilmGenreP TEXT,
        FilmGenreS TEXT,
        FilmGenreT TEXT,
        FilmGenreQ TEXT,
        FilmReleaseDate TEXT,
        FilmClassification TEXT,
        FilmDescription TEXT,
        FilmDirectors TEXT,
        FilmActors TEXT,
        FlimImageLink TEXT,
        FilmRating REAL DEFAULT 0,
        FilmReviewCount INTEGER DEFAULT 0
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS CommentList (
        CommentID INTEGER PRIMARY KEY AUTOINCREMENT,
        UserID INTEGER NOT NULL,
        MovieID INTEGER NOT NULL,
        CommentRating REAL,
        CommentContents TEXT,
        CommentTime TEXT,
        FOREIGN KEY (UserID) REFERENCES AccountsDetail(UserID),
        FOREIGN KEY (MovieID) REFERENCES MovieList(FilmID)
    )
    """)

    conn.commit()
    conn.close()

def seed_movies_if_empty():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM MovieList")
    count = cursor.fetchone()[0]

    if count > 0:
        conn.close()
        print("Movies already exist — skipping seed.")
        return

    print("Seeding movies...")

    movies = [
    (
        "Avatar: The Way of Water",
        "Sci-Fi", "Adventure", "Action", "Fantasy",
        "2022",
        "M",
        "Jake Sully protects his family among the ocean clans of Pandora. Jake Sully and Ney'tiri have formed a family and are doing everything to stay together. However, they must leave their home and explore the regions of Pandora. When an ancient threat resurfaces, Jake must fight a difficult war against the humans.",
        "James Cameron",
        "Sam Worthington, Zoe Saldaña",
        "https://m.media-amazon.com/images/I/71s3cEqEZTL._AC_UF1000,1000_QL80_.jpg"
    ),
    (
        "Avatar",
        "Sci-Fi", "Adventure", "Action", "Fantasy",
        "2009",
        "M",
        "Jake Sully, a paraplegic former Marine, becomes part of a corporate mission on the alien world of Pandora, where he bonds with the indigenous Na'vi and must choose between following orders or protecting his new home.",
        "James Cameron",
        "Sam Worthington, Zoe Saldaña, Sigourney Weaver",
        "https://m.media-amazon.com/images/M/MV5BMDEzMmQwZjctZWU2My00MWNlLWE0NjItMDJlYTRlNGJiZjcyXkEyXkFqcGc@._V1_FMjpg_UY2902_.jpg"
    ),
    (
        "Your Name.",
        "Romance", "Drama", "Fantasy", "Supernatural",
        "2016",
        "PG",
        "Two teenagers mysteriously begin swapping bodies, forming a deep connection that transcends distance and time as they try to meet in the real world.",
        "Makoto Shinkai",
        "Ryunosuke Kamiki, Mone Kamishiraishi",
        "https://m.media-amazon.com/images/M/MV5BMjI1ODZkYTgtYTY3Yy00ZTJkLWFkOTgtZDUyYWM4MzQwNjk0XkEyXkFqcGc@._V1_FMjpg_UY12000_.jpg"
    ),
    (
        "The Avengers",
        "Action", "Sci-Fi", "Adventure", "Superhero",
        "2012",
        "M",
        "Nick Fury of S.H.I.E.L.D. assembles a team of powerful heroes to stop Loki and his alien army from conquering Earth.",
        "Joss Whedon",
        "Robert Downey Jr., Chris Evans, Scarlett Johansson",
        "https://m.media-amazon.com/images/M/MV5BNGE0YTVjNzUtNzJjOS00NGNlLTgxMzctZTY4YTE1Y2Y1ZTU4XkEyXkFqcGc@._V1_FMjpg_UX800_.jpg"
    ),
    (
        "Avengers: Age of Ultron",
        "Action", "Sci-Fi", "Adventure", "Superhero",
        "2015",
        "M",
        "Tony Stark and Bruce Banner create an artificial intelligence called Ultron to protect humanity, but the sentient being turns against its creators, forcing the Avengers to stop a global extinction event.",
        "Joss Whedon",
        "Robert Downey Jr., Chris Evans, Scarlett Johansson",
        "https://m.media-amazon.com/images/M/MV5BODBhYTg1NGQtNGVmNS00ZTdiLThjYTYtZDFkNzRiNTZmNDZjXkEyXkFqcGc@._V1_FMjpg_UX864_.jpg"
    ),
    (
        "Avengers: Infinity War",
        "Action", "Sci-Fi", "Adventure", "Superhero",
        "2018",
        "M",
        "The Avengers and their allies unite to stop Thanos from collecting the Infinity Stones and carrying out his catastrophic plan to reshape the universe.",
        "Anthony Russo, Joe Russo",
        "Robert Downey Jr., Chris Evans, Josh Brolin",
        "https://m.media-amazon.com/images/M/MV5BMjMxNjY2MDU1OV5BMl5BanBnXkFtZTgwNzY1MTUwNTM@._V1_FMjpg_UY2048_.jpg"
    ),
    (
        "Avengers: Endgame",
        "Action", "Sci-Fi", "Adventure", "Superhero",
        "2019",
        "M",
        "After Thanos annihilates half of all life, the remaining Avengers assemble one final time to reverse his actions and restore balance to the universe.",
        "Anthony Russo, Joe Russo",
        "Robert Downey Jr., Chris Evans, Mark Ruffalo",
        "https://m.media-amazon.com/images/M/MV5BMTc5MDE2ODcwNV5BMl5BanBnXkFtZTgwMzI2NzQ2NzM@._V1_FMjpg_UY2048_.jpg"
    ),
    (
        "PK",
        "Comedy", "Drama", "Sci-Fi", "Satire",
        "2014",
        "M",
        "An innocent alien stranded on Earth embarks on a quest to retrieve his lost communication device, questioning religious dogma and social norms along the way.",
        "Rajkumar Hirani",
        "Aamir Khan, Anushka Sharma",
        "https://m.media-amazon.com/images/M/MV5BMTYzOTE2NjkxN15BMl5BanBnXkFtZTgwMDgzMTg0MzE@._V1_FMjpg_UX1090_.jpg"
    ),
    (
        "RRR",
        "Action", "Drama", "Historical", "Epic",
        "2022",
        "MA 15+",
        "Two legendary revolutionaries with opposing paths form an unbreakable bond and rise together to fight against British colonial rule in India.",
        "S. S. Rajamouli",
        "N. T. Rama Rao Jr., Ram Charan",
        "https://m.media-amazon.com/images/M/MV5BNWMwODYyMjQtMTczMi00NTQ1LWFkYjItMGJhMWRkY2E3NDAyXkEyXkFqcGc@._V1_FMjpg_UX750_.jpg"
    ),
    (
        "K.G.F: Chapter 1",
        "Action", "Drama", "Crime", "Thriller",
        "2018",
        "MA 15+",
        "Rocky, a young man, seeks power and wealth in order to fulfil a promise to his dying mother. His quest takes him to Mumbai, where he becomes entangled with the notorious gold mafia.",
        "Prashanth Neel",
        "Yash, Srinidhi Shetty",
        "https://m.media-amazon.com/images/M/MV5BM2M0YmIxNzItOWI4My00MmQzLWE0NGYtZTM3NjllNjIwZjc5XkEyXkFqcGc@._V1_FMjpg_UX500_.jpg"
    ),
    (
        "K.G.F: Chapter 2",
        "Action", "Drama", "Crime", "Thriller",
        "2022",
        "MA 15+",
        "Rocky rises as the leader and saviour of the Kolar Gold Fields, facing new enemies like Adheera, Inayat Khalil, and Ramika Sen while trying to fulfil his mother’s last wishes.",
        "Prashanth Neel",
        "Yash, Sanjay Dutt, Raveena Tandon",
        "https://m.media-amazon.com/images/M/MV5BZmQzZjVkZTUtYjI4ZC00ZDJmLWI0ZDUtZTFmMGM1Mzc5ZjIyXkEyXkFqcGc@._V1_FMjpg_UY2408_.jpg"
    ),
    (
        "Baahubali: The Beginning",
        "Action", "Adventure", "Fantasy", "Drama",
        "2015",
        "MA 15+",
        "In the kingdom of Mahishmati, Shivudu falls in love with a warrior woman and uncovers the conflict-ridden past of his family and his true legacy.",
        "S.S. Rajamouli",
        "Prabhas, Tamannaah, Rana Daggubati",
        "https://m.media-amazon.com/images/M/MV5BNmNlYWMyYWUtMmVlNy00MzFkLTgxYTQtYzQ5ZTU1ZGYyNjYyXkEyXkFqcGc@._V1_FMjpg_UX620_.jpg"
    ),
    (
        "Baahubali 2: The Conclusion",
        "Action", "Adventure", "Fantasy", "Drama",
        "2017",
        "MA 15+",
        "After discovering that his father was killed by Bhallaladeva, Mahendra Baahubali raises an army to defeat him and free his mother from captivity.",
        "S.S. Rajamouli",
        "Prabhas, Anushka Shetty, Rana Daggubati",
        "https://m.media-amazon.com/images/M/MV5BNTRhYTlhZTgtYmMyYy00NWI4LTk4MzItOWM2YjBmYTg2OTI2XkEyXkFqcGc@._V1_FMjpg_UX1129_.jpg"
    ),
    (
        "Baahubali: The Epic",
        "Action", "Adventure", "Fantasy", "Drama",
        "2017",
        "MA 15+",
        "Mahendra returns to the ancient kingdom of Mahishmati to avenge his father's death and reclaim his rightful place.",
        "S.S. Rajamouli",
        "Prabhas, Anushka Shetty, Rana Daggubati",
        "https://m.media-amazon.com/images/M/MV5BNmIwYTI3ODItMzRkOS00MzlhLWI4NzQtNDFmOGJhZGJhM2VkXkEyXkFqcGc@._V1_FMjpg_UX1080_.jpg"
    ),
    (
        "Golmaal Again",
        "Comedy", "Horror", "Family", "Drama",
        "2017",
        "M",
        "Five orphan men return to the orphanage they grew up in to attend their mentor's funeral. They encounter the ghost of their childhood friend, Khushi, and help her attain salvation.",
        "Rohit Shetty",
        "Ajay Devgn, Parineeti Chopra, Tabu",
        "https://m.media-amazon.com/images/M/MV5BZDljYzk0MzgtY2ZlMi00MjQ1LTk0MzYtZGFiZjdiM2VkMWU3XkEyXkFqcGc@._V1_FMjpg_UY2250_.jpg"
    ),
    (
        "Johnny English",
        "Comedy", "Action", "Spy", "Adventure",
        "2003",
        "PG",
        "After all MI5 agents are killed, the intellectually challenged yet confident spy Johnny English takes charge of all operations.",
        "Peter Howitt",
        "Rowan Atkinson, Natalie Imbruglia",
        "https://m.media-amazon.com/images/M/MV5BMTU0MGM4ZjQtNmQ3MC00NDE4LWEwYTItYWZiYzAxMGQwMDkzXkEyXkFqcGc@._V1_FMjpg_UX800_.jpg"
    ),
    (
        "Johnny English Reborn",
        "Comedy", "Action", "Spy", "Adventure",
        "2011",
        "PG",
        "Eight years after a failed mission, Johnny English returns to MI-7 to stop international assassins from killing the Chinese premier.",
        "Oliver Parker",
        "Rowan Atkinson, Rosamund Pike",
        "https://m.media-amazon.com/images/M/MV5BYjNhMTRlYWMtNGQzZS00OGFmLTlhOGUtODZlMDY4YzNlZDYwXkEyXkFqcGc@._V1_FMjpg_UX1013_.jpg"
    ),
    (
        "Johnny English Strikes Again",
        "Comedy", "Action", "Spy", "Adventure",
        "2018",
        "PG",
        "When a hacker exposes undercover agents in Britain, Johnny English is hired to find the culprit.",
        "David Kerr",
        "Rowan Atkinson, Ben Miller",
        "https://m.media-amazon.com/images/M/MV5BOTkzNTEzOTk5MV5BMl5BanBnXkFtZTgwNDk1OTYzNjM@._V1_FMjpg_UX510_.jpg"
    ),
    (
        "Inception",
        "Sci-Fi", "Action", "Thriller", "Mystery",
        "2010",
        "M",
        "Cobb steals information from targets by entering their dreams. Wanted for his wife's murder, his only chance at redemption is performing an impossible task.",
        "Christopher Nolan",
        "Leonardo DiCaprio, Joseph Gordon-Levitt, Ellen Page",
        "https://m.media-amazon.com/images/M/MV5BMjAxMzY3NjcxNF5BMl5BanBnXkFtZTcwNTI5OTM0Mw@@._V1_FMjpg_UX700_.jpg"
    ),
    (
        "The Matrix",
        "Sci-Fi", "Action", "Adventure", "Thriller",
        "1999",
        "M",
        "Neo, a hacker, discovers the reality he lives in is a simulated world, and joins Morpheus to learn the truth.",
        "Lana Wachowski, Lilly Wachowski",
        "Keanu Reeves, Laurence Fishburne, Carrie-Anne Moss",
        "https://m.media-amazon.com/images/M/MV5BN2NmN2VhMTQtMDNiOS00NDlhLTliMjgtODE2ZTY0ODQyNDRhXkEyXkFqcGc@._V1_FMjpg_UY3156_.jpg"
    ),
    (
        "Matrix Reloaded",
        "Action", "Sci-Fi", "Adventure", "Thriller",
        "2003",
        "M",
        "Neo attempts to rescue the Keymaker from the Merovingian. He must confront the Architect to save Zion, while Zion prepares for war against the machines.",
        "Lana Wachowski, Lilly Wachowski",
        "Keanu Reeves, Laurence Fishburne, Carrie-Anne Moss",
        "https://m.media-amazon.com/images/M/MV5BNjAxYjkxNjktYTU0YS00NjFhLWIyMDEtMzEzMTJjMzRkMzQ1XkEyXkFqcGc@._V1_FMjpg_UX800_.jpg"
    ),
    (
        "Matrix Revolutions",
        "Action", "Sci-Fi", "Adventure", "Thriller",
        "2003",
        "M",
        "Neo attempts to broker peace between humans and machines to save Zion, confronting his arch-nemesis, the rogue agent Smith.",
        "Lana Wachowski, Lilly Wachowski",
        "Keanu Reeves, Laurence Fishburne, Carrie-Anne Moss",
        "https://m.media-amazon.com/images/M/MV5BMmNmMTEzODQtNmExMS00OGUxLWFkNTItMTM3NzBlNDk0YWU5XkEyXkFqcGc@._V1_FMjpg_UY3251_.jpg"
    ),
    (
        "The Matrix Resurrections",
        "Action", "Sci-Fi", "Adventure", "Thriller",
        "2021",
        "M",
        "Thomas Anderson accepts Morpheus's offer and discovers a new, more secure, and dangerous Matrix.",
        "Lana Wachowski",
        "Keanu Reeves, Carrie-Anne Moss, Yahya Abdul-Mateen II",
        "https://m.media-amazon.com/images/M/MV5BMDMyNDIzYzMtZTMyMy00NjUyLWI3Y2MtYzYzOGE1NzQ1MTBiXkEyXkFqcGc@._V1_FMjpg_UY4096_.jpg"
    ),
    (
        "Pirates of the Caribbean: The Curse of the Black Pearl",
        "Action", "Adventure", "Fantasy", "Comedy",
        "2003",
        "M",
        "Will joins Captain Jack Sparrow to rescue Elizabeth, kidnapped due to her supposed possession of Jack's medallion.",
        "Gore Verbinski",
        "Johnny Depp, Orlando Bloom, Keira Knightley",
        "https://m.media-amazon.com/images/M/MV5BNDhlMzEyNzItMTA5Mi00YWRhLThlNTktYTQyMTA0MDIyNDEyXkEyXkFqcGc@._V1_FMjpg_UX671_.jpg"
    ),
    (
        "Pirates of the Caribbean: Dead Man's Chest",
        "Action", "Adventure", "Fantasy", "Comedy",
        "2006",
        "M",
        "Jack Sparrow seeks the heart of Davy Jones to avoid enslavement. Will and Elizabeth also have their own motives.",
        "Gore Verbinski",
        "Johnny Depp, Orlando Bloom, Keira Knightley",
        "https://m.media-amazon.com/images/M/MV5BMTcwODc1MTMxM15BMl5BanBnXkFtZTYwMDg1NzY3._V1_FMjpg_UX450_.jpg"
    ),
    (
        "Pirates of the Caribbean: At World's End",
        "Action", "Adventure", "Fantasy", "Comedy",
        "2007",
        "M",
        "Will Turner and Elizabeth Swann team up with Barbossa to rescue Jack Sparrow and confront the Flying Dutchman.",
        "Gore Verbinski",
        "Johnny Depp, Orlando Bloom, Keira Knightley",
        "https://m.media-amazon.com/images/M/MV5BMjIyNjkxNzEyMl5BMl5BanBnXkFtZTYwMjc3MDE3._V1_FMjpg_UX450_.jpg"
    ),
    (
        "Pirates of the Caribbean: On Stranger Tides",
        "Action", "Adventure", "Fantasy", "Comedy",
        "2011",
        "M",
        "Jack Sparrow searches for the Fountain of Youth, encountering a mysterious woman and facing his old enemy Blackbeard.",
        "Rob Marshall",
        "Johnny Depp, Penélope Cruz, Ian McShane",
        "https://m.media-amazon.com/images/M/MV5BMjE5MjkwODI3Nl5BMl5BanBnXkFtZTcwNjcwMDk4NA@@._V1_FMjpg_UX1114_.jpg"
    ),
    (
        "Pirates of the Caribbean: Dead Men Tell No Tales",
        "Action", "Adventure", "Fantasy", "Comedy",
        "2017",
        "M",
        "Jack Sparrow and Henry Turner search for the Trident of Poseidon to break the Flying Dutchman's curse and stop Captain Salazar.",
        "Joachim Rønning, Espen Sandberg",
        "Johnny Depp, Brenton Thwaites, Kaya Scodelario",
        "https://m.media-amazon.com/images/M/MV5BMTYyMTcxNzc5M15BMl5BanBnXkFtZTgwOTg2ODE2MTI@._V1_FMjpg_UY2048_.jpg"
    ),
    (
        "Star Wars: Episode IV - A New Hope",
        "Sci-Fi", "Adventure", "Action", "Fantasy",
        "1977",
        "PG",
        "Princess Leia is abducted by Darth Vader. Luke teams up with a Jedi, a pilot, and two droids to save her and the galaxy.",
        "George Lucas",
        "Mark Hamill, Carrie Fisher, Harrison Ford",
        "https://m.media-amazon.com/images/M/MV5BOGUwMDk0Y2MtNjBlNi00NmRiLTk2MWYtMGMyMDlhYmI4ZDBjXkEyXkFqcGc@._V1_FMjpg_UY2937_.jpg"
    ),
    (
        "Star Wars: Episode V - The Empire Strikes Back",
        "Sci-Fi", "Adventure", "Action", "Fantasy",
        "1980",
        "PG",
        "The Rebel Alliance fights the Galactic Empire while Luke Skywalker attempts to master the Force and become a Jedi.",
        "Irvin Kershner",
        "Mark Hamill, Carrie Fisher, Harrison Ford",
        "https://m.media-amazon.com/images/M/MV5BMTkxNGFlNDktZmJkNC00MDdhLTg0MTEtZjZiYWI3MGE5NWIwXkEyXkFqcGc@._V1_FMjpg_UY2883_.jpg"
    ),
    (
        "Star Wars: Episode VI - Return of the Jedi",
        "Sci-Fi", "Adventure", "Action", "Fantasy",
        "1983",
        "PG",
        "Luke Skywalker tries to bring his father to the light side while the rebels hatch a plan to destroy the second Death Star.",
        "Richard Marquand",
        "Mark Hamill, Carrie Fisher, Harrison Ford",
        "https://m.media-amazon.com/images/M/MV5BNWEwOTI0MmUtMGNmNy00ODViLTlkZDQtZTg1YmQ3MDgyNTUzXkEyXkFqcGc@._V1_FMjpg_UY2809_.jpg"
    ),
    (
        "Star Wars: Episode I - The Phantom Menace",
        "Sci-Fi", "Adventure", "Action", "Fantasy",
        "1999",
        "PG",
        "Jedi Qui-Gon and Obi-Wan protect a princess and discover a boy strong in the Force.",
        "George Lucas",
        "Liam Neeson, Ewan McGregor, Natalie Portman",
        "https://m.media-amazon.com/images/M/MV5BODVhNGIxOGItYWNlMi00YTA0LWI3NTctZmQxZGUwZDEyZWI4XkEyXkFqcGc@._V1_FMjpg_UX1230_.jpg"
    ),
    (
        "Star Wars: Episode II - Attack of the Clones",
        "Sci-Fi", "Adventure", "Action", "Fantasy",
        "2002",
        "PG",
        "Obi-Wan uncovers a plot to destroy the Republic, and the Jedi must defend the galaxy against the Sith.",
        "George Lucas",
        "Ewan McGregor, Natalie Portman, Hayden Christensen",
        "https://m.media-amazon.com/images/M/MV5BNTgxMjY2YzUtZmVmNC00YjAwLWJlODMtNDBhNzllNzIzMjgxXkEyXkFqcGc@._V1_FMjpg_UY3091_.jpg"
    ),
    (
        "Star Wars: Episode III - Revenge of the Sith",
        "Sci-Fi", "Adventure", "Action", "Fantasy",
        "2005",
        "M",
        "Anakin falls prey to Palpatine and the Jedi's mind games, giving into temptation.",
        "George Lucas",
        "Ewan McGregor, Natalie Portman, Hayden Christensen",
        "https://m.media-amazon.com/images/M/MV5BNTc4MTc3NTQ5OF5BMl5BanBnXkFtZTcwOTg0NjI4NA@@._V1_FMjpg_UX1152_.jpg"
    ),
    (
        "Star Wars: The Force Awakens",
        "Sci-Fi", "Adventure", "Action", "Fantasy",
        "2015",
        "M",
        "Finn, Rey, and Poe must stop a new order from destroying the New Republic and find the last surviving Jedi, Luke.",
        "J.J. Abrams",
        "Daisy Ridley, John Boyega, Harrison Ford",
        "https://m.media-amazon.com/images/M/MV5BOTAzODEzNDAzMl5BMl5BanBnXkFtZTgwMDU1MTgzNzE@._V1_FMjpg_UY3240_.jpg"
    ),
    (
        "Star Wars: The Last Jedi",
        "Sci-Fi", "Adventure", "Action", "Fantasy",
        "2017",
        "M",
        "Luke trains Rey to assist the Resistance against the First Order while she develops her powers.",
        "Rian Johnson",
        "Daisy Ridley, John Boyega, Mark Hamill",
        "https://m.media-amazon.com/images/M/MV5BMjQ1MzcxNjg4N15BMl5BanBnXkFtZTgwNzgwMjY4MzI@._V1_FMjpg_UX800_.jpg"
    ),
    (
        "Star Wars: The Rise of Skywalker",
        "Sci-Fi", "Adventure", "Action", "Fantasy",
        "2019",
        "M",
        "Emperor Palpatine is resurrected, and the Jedi face off against the Sith in the final battle of the saga.",
        "J.J. Abrams",
        "Daisy Ridley, John Boyega, Adam Driver",
        "https://m.media-amazon.com/images/M/MV5BODg5ZTNmMTUtYThlNy00NjljLWE0MGUtYmQ1NDg4NWU5MjQ1XkEyXkFqcGc@._V1_FMjpg_UY2048_.jpg"
    ),
        (
        "One Piece Film: Red",
        "Adventure", "Fantasy", "Action", "Music",
        "2022",
        "PG",
        "Uta is a beloved singer, renowned for concealing her identity. For the first time ever, she reveals herself at a live concert.",
        "Gorō Taniguchi",
        "Kaori Nazuka, Kazuya Nakai, Shunya Shiraishi",
        "https://m.media-amazon.com/images/M/MV5BNTdjY2YxYTQtNjIzYy00ZDczLThhNTUtNmY2ZWNkZjZiMTYzXkEyXkFqcGc@._V1_FMjpg_UY5603_.jpg"
    ),
    (
        "Chainsaw Man - The Movie: Reze Arc",
        "Action", "Horror", "Supernatural", "Thriller",
        "2025",
        "MA 15+",
        "Chainsaw Man faces his deadliest battle yet in a brutal war between devils, hunters, and secret enemies.",
        "Ryu Nakayama",
        "Kikunosuke Toya, Reina Ueda, Tomori Kusunoki",
        "https://m.media-amazon.com/images/M/MV5BNDQzMjc2ZDQtMjY2NS00M2UxLTg2OTktNWVjZmY5YjA4MzVhXkEyXkFqcGc@._V1_FMjpg_UX1079_.jpg"
    ),
    (
        "Howl's Moving Castle",
        "Fantasy", "Adventure", "Romance", "Family",
        "2004",
        "PG",
        "Jealous of Sophie's closeness to Howl, the Witch of Waste transforms her into an old lady. Sophie must break the spell with Howl's friends, Calcifer and Markl.",
        "Hayao Miyazaki",
        "Chieko Baishō, Takuya Kimura, Akihiro Miwa",
        "https://m.media-amazon.com/images/M/MV5BNzlhNzlmZjktMTkyNC00ODBkLTlkZjctODAyMGRiYzQyMThmXkEyXkFqcGc@._V1_FMjpg_UX667_.jpg"
    ),
    (
        "The Lord of the Rings: The Fellowship of the Ring",
        "Fantasy", "Adventure", "Action", "Drama",
        "2001",
        "M",
        "A ring with mysterious powers lands with Frodo. Guided by Gandalf, he and his friends embark on a journey to the Elvish kingdom.",
        "Peter Jackson",
        "Elijah Wood, Ian McKellen, Orlando Bloom",
        "https://m.media-amazon.com/images/M/MV5BNzIxMDQ2YTctNDY4MC00ZTRhLTk4ODQtMTVlOWY4NTdiYmMwXkEyXkFqcGc@._V1_FMjpg_UY2936_.jpg"
    ),
    (
        "The Lord of the Rings: The Two Towers",
        "Fantasy", "Adventure", "Action", "Drama",
        "2002",
        "M",
        "Frodo and Sam arrive in Mordor with Gollum's help. Allies join to defend Isengard as Saruman launches his assault.",
        "Peter Jackson",
        "Elijah Wood, Ian McKellen, Viggo Mortensen",
        "https://m.media-amazon.com/images/M/MV5BMGQxMDdiOWUtYjc1Ni00YzM1LWE2NjMtZTg3Y2JkMjEzMTJjXkEyXkFqcGc@._V1_FMjpg_UX964_.jpg"
    ),
    (
        "The Lord of the Rings: The Return of the King",
        "Fantasy", "Adventure", "Action", "Drama",
        "2003",
        "M",
        "The Fellowship prepares for the final battle. Frodo and Sam approach Mount Doom to destroy the One Ring, following Gollum unknowingly.",
        "Peter Jackson",
        "Elijah Wood, Ian McKellen, Viggo Mortensen",
        "https://m.media-amazon.com/images/M/MV5BMTZkMjBjNWMtZGI5OC00MGU0LTk4ZTItODg2NWM3NTVmNWQ4XkEyXkFqcGc@._V1_FMjpg_UX800_.jpg"
    ),
    (
        "A Minecraft Movie",
        "Adventure", "Fantasy", "Family", "Comedy",
        "2025",
        "PG",
        "A mysterious portal pulls four misfits into the Overworld. To get back home, they'll master the terrain with the help of Steve.",
        "Aaron Horvath & Peter Rida Michail",
        "Jason Momoa, Jack Black, Emma Myers",
        "https://m.media-amazon.com/images/M/MV5BMjA0MWY0NTktMjJlNi00ZjhkLWI2ZTMtZDc0MjgxMjRkNzdkXkEyXkFqcGc@._V1_FMjpg_UY712_.jpg"
    ),
        (
        "Rush Hour", "Action", "Comedy", "Crime", "Adventure",
        "1998", "M",
        "Two cops from different cultures, who cannot stand each other, team up to save the kidnapped 11-year-old daughter of a diplomat.",
        "Brett Ratner",
        "Jackie Chan, Chris Tucker", 
        "https://m.media-amazon.com/images/M/MV5BMGZiMzViNmEtNTNlZi00MzFmLTk5NTEtNDE2OTUzNmNlMTY4XkEyXkFqcGc@._V1_FMjpg_UX850_.jpg"
    ),
    (
        "Rush Hour 2", "Action", "Comedy", "Crime", "Adventure",
        "2001", "M",
        "While vacationing in Hong Kong, Lee is assigned to solve a case after a bomb kills two undercover agents.",
        "Brett Ratner",
        "Jackie Chan, Chris Tucker", 
        "https://m.media-amazon.com/images/M/MV5BMGM0OTM4NGYtYzkzMC00OGZmLWEwZTItOTg4ZTdkYTIxOTc0XkEyXkFqcGc@._V1_FMjpg_UX1011_.jpg"
    ),
    (
        "Rush Hour 3", "Action", "Comedy", "Crime", "Adventure",
        "2007", "M",
        "Inspector Lee and Detective Carter arrive in Paris following a murder attempt on Ambassador Han and track down the Triads' secret leaders.",
        "Brett Ratner",
        "Jackie Chan, Chris Tucker", 
        "https://m.media-amazon.com/images/M/MV5BMTA0Nzg5NjQ0MDBeQTJeQWpwZ15BbWU3MDE4Mzg5NDE@._V1_FMjpg_UX510_.jpg"
    ),
    (
        "Ip Man", "Action", "Biography", "Drama", "History",
        "2008", "MA 15+",
        "After the Japanese invasion, Ip Man refuses to train enemy soldiers despite his skills becoming known.",
        "Wilson Yip",
        "Donnie Yen", 
        "https://m.media-amazon.com/images/M/MV5BZmJjZDE0MmYtNzgwYy00NTg2LWE0NDYtNzA0YTA4MjA0NmYxXkEyXkFqcGc@._V1_FMjpg_UX1000_.jpg"
    ),
    (
        "Kung Fu Panda", "Animation", "Action", "Comedy", "Family",
        "2008", "G",
        "Po, a kung fu enthusiast, is selected as the Dragon Warrior and must team up with the Furious Five to defeat evil forces.",
        "Mark Osborne & John Stevenson",
        "Jack Black, Dustin Hoffman", 
        "https://m.media-amazon.com/images/M/MV5BZDU5MDNiMGItYjVmZi00NDUxLTg2OTktNGE0NzNlNzM4NzgyXkEyXkFqcGc@._V1_FMjpg_UY2048_.jpg"
    ),
    (
        "Kung Fu Panda 2", "Animation", "Action", "Comedy", "Family",
        "2011", "G",
        "Dragon Warrior Po uncovers the mystery of his past while stopping the evil peacock Shen from conquering China.",
        "Jennifer Yuh Nelson",
        "Jack Black, Angelina Jolie", 
        "https://m.media-amazon.com/images/M/MV5BYmIxMGYzMTUtZDQzYy00ODc4LWE1YzQtZGMwYTc0YTYyYTE0XkEyXkFqcGc@._V1_FMjpg_UX482_.jpg"
    ),
    (
        "Kung Fu Panda 3", "Animation", "Action", "Comedy", "Family",
        "2016", "G",
        "Po must train a group of pandas to master kung fu to defeat the wicked supernatural warrior Kai.",
        "Jennifer Yuh Nelson & Alessandro Carloni",
        "Jack Black, Bryan Cranston", 
        "https://m.media-amazon.com/images/M/MV5BMTUyNzgxNjg2M15BMl5BanBnXkFtZTgwMTY1NDI1NjE@._V1_FMjpg_UX660_.jpg"
    ),
    (
        "Ice Age", "Animation", "Adventure", "Comedy", "Family",
        "2002", "G",
        "Manny, Sid, and Diego help return a human baby to his father during the onset of an ice age.",
        "Chris Wedge",
        "Ray Romano, John Leguizamo", 
        "https://m.media-amazon.com/images/M/MV5BMDBlYzU2OGMtOGJjNi00ZGZjLWIwNjMtYzdiZjkwYWNjZDljXkEyXkFqcGc@._V1_FMjpg_UX691_.jpg"
    ),
    (
        "Ice Age: The Meltdown", "Animation", "Adventure", "Comedy", "Family",
        "2006", "G",
        "Manny, Sid, and Diego search for higher ground as water bursts from a glacier, caused by Scrat's acorn mishap.",
        "Carlos Saldanha",
        "Ray Romano, John Leguizamo", 
        "https://m.media-amazon.com/images/M/MV5BMjAwODg3OTAxMl5BMl5BanBnXkFtZTcwMjg2NjYyMw@@._V1_FMjpg_UY2048_.jpg"
    ),
    (
        "Ice Age: Dawn of the Dinosaurs", "Animation", "Adventure", "Comedy", "Family",
        "2009", "G",
        "Manny and Ellie expect their first child while Sid steals dinosaur eggs, leading to a rescue mission.",
        "Carlos Saldanha",
        "Ray Romano, John Leguizamo", 
        "https://m.media-amazon.com/images/M/MV5BZWJjZDYwMjgtZDZiMy00YzcyLThjN2YtYjI1ZDQ2ZDJkOTVmXkEyXkFqcGc@._V1_FMjpg_UY2110_.jpg"
    ),
    (
        "Ice Age: Continental Drift", "Animation", "Adventure", "Comedy", "Family",
        "2012", "G",
        "Scrat's nut-chasing antics cause a continental drift, dragging Manny, Diego, and Sid into another adventure.",
        "Steve Martino & Mike Thurmeier",
        "Ray Romano, John Leguizamo", 
        "https://m.media-amazon.com/images/M/MV5BMTM3NDM5MzY5Ml5BMl5BanBnXkFtZTcwNjExMDUwOA@@._V1_FMjpg_UY2000_.jpg"
    ),
    (
        "Madagascar", "Animation", "Comedy", "Adventure", "Family",
        "2005", "G",
        "Four animals from New York Central Zoo escape to Madagascar, where they meet happy lemurs.",
        "Eric Darnell & Tom McGrath",
        "Ben Stiller, Chris Rock", 
        "https://m.media-amazon.com/images/M/MV5BYjk4OGFmZmYtYWE4NC00MzM4LTkwZTItODdhMjk3NTZjMmI5XkEyXkFqcGc@._V1_FMjpg_UX960_.jpg"
    ),
    (
        "Madagascar: Escape 2 Africa", "Animation", "Comedy", "Adventure", "Family",
        "2008", "G",
        "Alex reunites with his long-lost parents in Africa while Makunga tries to become king of the jungle.",
        "Eric Darnell & Tom McGrath",
        "Ben Stiller, Chris Rock", 
        "https://m.media-amazon.com/images/M/MV5BMjExMDA4NDcwMl5BMl5BanBnXkFtZTcwODAxNTQ3MQ@@._V1_FMjpg_UX550_.jpg"
    ),
    (
        "Madagascar 3: Europe's Most Wanted", "Animation", "Comedy", "Adventure", "Family",
        "2012", "G",
        "The zoo animals travel across Europe with a circus troupe while being chased by animal control.",
        "Eric Darnell & Tom McGrath",
        "Ben Stiller, Chris Rock", 
        "https://m.media-amazon.com/images/M/MV5BYTM5OWRiZTAtOTNkMS00NzNhLTkwYmYtMWI1MzkyMjE3MWE1XkEyXkFqcGc@._V1_FMjpg_UX800_.jpg"
    ),
    (
        "Guardians of the Galaxy", "Action", "Adventure", "Comedy", "Sci-Fi",
        "2014", "M",
        "A group of skilled criminals led by Peter Quill join forces to stop villain Ronan the Accuser, who wants a mystical orb to control the universe.",
        "James Gunn",
        "Chris Pratt, Zoe Saldana, Dave Bautista",
        "https://m.media-amazon.com/images/M/MV5BM2ZmNjQ2MzAtNDlhNi00MmQyLWJhZDMtNmJiMjFlOWY4MzcxXkEyXkFqcGc@._V1_FMjpg_UX1012_.jpg"
    ),
    (
        "Guardians of the Galaxy Vol. 2", "Action", "Adventure", "Comedy", "Sci-Fi",
        "2017", "M",
        "After a successful mission, Peter Quill and his team meet Ego, who claims to be Peter's father, but uncover disturbing truths.",
        "James Gunn",
        "Chris Pratt, Zoe Saldana, Dave Bautista",
        "https://m.media-amazon.com/images/M/MV5BNWE5MGI3MDctMmU5Ni00YzI2LWEzMTQtZGIyZDA5MzQzNDBhXkEyXkFqcGc@._V1_FMjpg_UX509_.jpg"
    ),
    (
        "Guardians of the Galaxy Vol. 3", "Action", "Adventure", "Comedy", "Sci-Fi",
        "2023", "M",
        "Peter Quill and his team must rally to defend the universe and protect one of their own, or risk the end of the Guardians.",
        "James Gunn",
        "Chris Pratt, Zoe Saldana, Dave Bautista",
        "https://m.media-amazon.com/images/M/MV5BOTJhOTMxMmItZmE0Ny00MDc3LWEzOGEtOGFkMzY4MWYyZDQ0XkEyXkFqcGc@._V1_FMjpg_UX886_.jpg"
    ),
    (
        "Doctor Strange", "Action", "Adventure", "Fantasy", "Sci-Fi",
        "2016", "M",
        "After losing the use of his hands, Stephen Strange trains under the Ancient One and becomes a master sorcerer.",
        "Scott Derrickson",
        "Benedict Cumberbatch, Chiwetel Ejiofor",
        "https://m.media-amazon.com/images/M/MV5BNjgwNzAzNjk1Nl5BMl5BanBnXkFtZTgwMzQ2NjI1OTE@._V1_FMjpg_UY2048_.jpg"
    ),
    (
        "Doctor Strange in the Multiverse of Madness", "Action", "Adventure", "Fantasy", "Sci-Fi",
        "2022", "M",
        "Doctor Strange teams with a mysterious teenage girl to battle multiverse threats, including alternate versions of himself.",
        "Sam Raimi",
        "Benedict Cumberbatch, Elizabeth Olsen",
        "https://m.media-amazon.com/images/M/MV5BMGMwYmVlYTEtYmZhMC00ZDQ3LTgwNWMtZjBkNjEzZDkxOWFlXkEyXkFqcGc@._V1_FMjpg_UX756_.jpg"
    ),
    (
        "Jurassic Park", "Adventure", "Sci-Fi", "Action", "Adventure", 
        "1993", "PG", 
        "An industrialist invites some experts to visit his theme park of cloned dinosaurs. After a power failure, the creatures run loose, putting everyone's lives, including his grandchildren's, in danger.", 
        "Steven Spielberg", 
        "Sam Neill, Laura Dern, Jeff Goldblum", 
        "https://m.media-amazon.com/images/M/MV5BMjM2MDgxMDg0Nl5BMl5BanBnXkFtZTgwNTM2OTM5NDE@._V1_FMjpg_UX667_.jpg"
    ),
    (
        "Whiplash", "Drama", "Music", "Psychological", "Drama", 
        "2014", "M", 
        "Andrew enrols in a music conservatory to become a drummer. But he is mentored by Terence Fletcher, whose unconventional training methods push him beyond the boundaries of reason and sensibility.", 
        "Damien Chazelle", 
        "Miles Teller, J.K. Simmons", 
        "https://m.media-amazon.com/images/M/MV5BMDFjOWFkYzktYzhhMC00NmYyLTkwY2EtYjViMDhmNzg0OGFkXkEyXkFqcGc@._V1_FMjpg_UY5333_.jpg"
    ),
    (
        "KPop Demon Hunters", "Action", "Fantasy", "Music", "Adventure", 
        "2025", "M", 
        "When K-pop superstars Rumi, Mira and Zoey aren't selling out stadiums or topping the Billboard charts, they're moonlighting as demon hunters to protect their fans from ever-present supernatural danger.", 
        "Saja Boys", 
        "Rumi, Mira, Zoey", 
        "https://m.media-amazon.com/images/M/MV5BNTBiYWJlMjQtOTIyMy00NTY4LWFhOWItOWZhNzc3NGMyMjc2XkEyXkFqcGc@._V1_FMjpg_UX1013_.jpg"
    ),
    (
        "Interstellar", "Sci-Fi", "Adventure", "Drama", "Sci-Fi", 
        "2014", "M", 
        "When Earth becomes uninhabitable in the future, a farmer and ex-NASA pilot, Joseph Cooper, is tasked to pilot a spacecraft, along with a team of researchers, to find a new planet for humans.", 
        "Christopher Nolan", 
        "Matthew McConaughey, Anne Hathaway, Jessica Chastain", 
        "https://m.media-amazon.com/images/M/MV5BYzdjMDAxZGItMjI2My00ODA1LTlkNzItOWFjMDU5ZDJlYWY3XkEyXkFqcGc@._V1_FMjpg_UY3600_.jpg"
    ),
    (
        "The Dark Knight", "Action", "Crime", "Drama", "Thriller", 
        "2008", "M", 
        "Batman has a new foe, the Joker, who is an accomplished criminal hell-bent on decimating Gotham City. Together with Gordon and Harvey Dent, Batman struggles to thwart the Joker before it is too late.", 
        "Christopher Nolan", 
        "Christian Bale, Heath Ledger, Aaron Eckhart", 
        "https://m.media-amazon.com/images/M/MV5BMTMxNTMwODM0NF5BMl5BanBnXkFtZTcwODAyMTk2Mw@@._V1_FMjpg_UY2048_.jpg"
    )
    ]



    cursor.executemany("""
        INSERT INTO MovieList (
            FilmName, FilmGenreP, FilmGenreS, FilmGenreT, FilmGenreQ,
            FilmReleaseDate, FilmClassification, FilmDescription,
            FilmDirectors, FilmActors, FlimImageLink
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, movies)

    conn.commit()
    conn.close()
    print("Movie seeding complete.")


init_db()
seed_movies_if_empty()

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]

        if len(username) > 16:
            return render_template("signup.html", error="Username too long")

        if profanity.contains_profanity(username):
            return render_template("signup.html", error="Inappropriate username")

        if len(password) < 8:
            return render_template("signup.html", error="Password must be 8+ chars")

        if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email):
            return render_template("signup.html", error="Invalid email")

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM AccountsDetail WHERE Username=? OR UserEmail=?",
            (username, email)
        )

        if cursor.fetchone():
            conn.close()
            return render_template("signup.html", error="User already exists")

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
        INSERT INTO AccountsDetail
        (Username, UserPassword, UserEmail, UserPFP, UserJoinDate, UserTitle, UserDescription)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, hashed, email, "default.png", now, "New User", "No bio yet"))

        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form["identifier"]
        password = request.form["password"]

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
        SELECT Username, UserPassword, UserAuthorityLevel
        FROM AccountsDetail
        WHERE Username=? OR UserEmail=?
        """, (identifier, identifier))

        user = cursor.fetchone()
        conn.close()

        if not user:
            return render_template("login.html", error="User not found")

        username, hashed, level = user

        if not bcrypt.checkpw(password.encode(), hashed.encode()):
            return render_template("login.html", error="Incorrect password")

        session["user"] = username
        session["level"] = level

        return redirect("/browse")

    return render_template("login.html")

#FOLLOWING ROUTES REQUIRE LOGIN TO ACCESS - COOKIES STORE THIS DATA. 
@app.route("/browse")
def browse():

    query = request.args.get("q", "").strip()
    genre = request.args.get("genre", "").strip()

    conn = get_db()
    cursor = conn.cursor()

    sql = """
        SELECT FilmID, FilmName, FilmReleaseDate, FilmRating, FlimImageLink
        FROM MovieList
        WHERE 1=1
    """
    params = []

    # SEARCH BY TITLE
    if query:
        sql += " AND FilmName LIKE ?"
        params.append(f"%{query}%")

    # GENRE FILTERS 
    if genre:
        sql += """
        AND (
            FilmGenreP = ?
            OR FilmGenreS = ?
            OR FilmGenreT = ?
            OR FilmGenreQ = ?
        )
        """
        params.extend([genre, genre, genre, genre])

    sql += " ORDER BY FilmID ASC"

    cursor.execute(sql, params)
    movies = cursor.fetchall()
    conn.close()

    return render_template(
        "browse.html",
        user=session.get("user"),
        movies=movies
    )






@app.route("/top10")
def top10():
    if "user" not in session:
        return redirect("/login")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            FilmID,
            FilmName,
            FlimImageLink
        FROM MovieList
        ORDER BY RANDOM()
        LIMIT 10
    """)

    movies = cursor.fetchall()
    conn.close()

    return render_template(
        "top10.html",
        movies=movies
    )



@app.route("/movie", methods=["GET", "POST"])
def movie():

    movie_id = request.args.get("id", type=int)
    if not movie_id:
        return redirect("/browse")

    conn = get_db()
    cursor = conn.cursor()

    # Fetch movie by FilmID (NOT name)
    cursor.execute("""
        SELECT
            FilmID,              -- 0
            FilmName,            -- 1
            FilmReleaseDate,     -- 2
            FilmRating,          -- 3
            FlimImageLink,       -- 4
            FilmDescription,     -- 5
            FilmGenreP,          -- 6
            FilmGenreS,          -- 7
            FilmGenreT,          -- 8
            FilmGenreQ,          -- 9
            FilmTrailerURL,      -- 10 
            FilmDirectors,        -- 11
            FilmActors,          -- 12
            FilmClassification   -- 13
        FROM MovieList
        WHERE FilmID=?
    """, (movie_id,))

    movie = cursor.fetchone()

   ### FETCH COMMENTS
    cursor.execute("""
        SELECT
            AccountsDetail.Username,        -- 0
            AccountsDetail.UserPFP,         -- 1
            CommentList.CommentRating,      -- 2
            CommentList.CommentContents,    -- 3
            CommentList.CommentTime         -- 4
        FROM CommentList
        JOIN AccountsDetail
        ON CommentList.UserID = AccountsDetail.UserID
        WHERE MovieID=?
        ORDER BY CommentTime DESC
    """, (movie_id,))
    comments = cursor.fetchall()



    if not movie:
        conn.close()
        return redirect("/browse")

    # HANDLE POST (DEALING WITH NEW COMMENTS)
    if request.method == "POST":
        if "user" not in session:
            conn.close()
            return redirect("/login")
        try:
            rating = int(request.form["rating"])
        except ValueError:
            return render_template(
                "movie.html",
                movie=movie,
                comments=comments,
                error="Rating must be a whole number between 0 and 10."
            )

        if rating < 0 or rating > 10:
            return render_template(
                "movie.html",
                movie=movie,
                comments=comments,
                error="Rating must be between 0 and 10."
            )

        comment = request.form["comment"]

        cursor.execute(
            "SELECT UserID FROM AccountsDetail WHERE Username=?",
            (session["user"],)
        )
        user_id = cursor.fetchone()[0]

        # CHECK IF USER HAS ALREADY REVIEWED THIS MOVIE
        cursor.execute("""
            SELECT 1
            FROM CommentList
            WHERE UserID = ? AND MovieID = ?
        """, (user_id, movie_id))

        already_reviewed = cursor.fetchone()

        if already_reviewed:
            conn.close()
            return render_template(
                "redirect_alert.html",
                message="You have already reviewed this movie.",
                redirect_url="/browse"
            )


        cursor.execute("""
            INSERT INTO CommentList
            (UserID, MovieID, CommentRating, CommentContents, CommentTime)
            VALUES (?, ?, ?, ?, ?)
        """, (
            user_id,
            movie_id,
            rating,
            comment,
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        cursor.execute("""
            UPDATE AccountsDetail
            SET UserReviewCount = UserReviewCount + 1
            WHERE UserID=?
        """, (user_id,))

        cursor.execute("""
            UPDATE MovieList
            SET FilmRating = ROUND((
                SELECT AVG(CommentRating)
                FROM CommentList
                WHERE MovieID = ?
            ), 1)
            WHERE FilmID = ?
""", (movie_id, movie_id))


        conn.commit()
        return redirect(f"/movie?id={movie_id}")

    # FETCH COMMENTS
    cursor.execute("""
        SELECT Username, CommentRating, CommentContents, CommentTime
        FROM CommentList
        JOIN AccountsDetail USING(UserID)
        WHERE MovieID=?
        ORDER BY CommentTime DESC
    """, (movie_id,))
    comments = cursor.fetchall()

    conn.close()

    return render_template(
        "movie.html",
        movie=movie,
        comments=comments
    )


@app.route("/logout")
def logout():
    print("Before logout:", dict(session))
    session.clear()
    print("After logout:", dict(session))
    return redirect("/login")

#PROFILE PAGE ROUTE TO DISPLAY USER INFORMATION - NEEDS LOGIN TO ACCESS.
@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect("/login")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT Username, UserEmail, UserPFP, UserJoinDate,
           UserReviewCount, UserTitle, UserDescription
    FROM AccountsDetail
    WHERE Username=?
    """, (session["user"],))

    user = cursor.fetchone()
    conn.close()

    if not user:
        return redirect("/logout")

    return render_template(
        "profile.html",
        username=user[0],
        email=user[1],
        pfp=user[2],
        joined=user[3],
        reviews=user[4],
        title=user[5],
        bio=user[6]
    )
#USERNAME PROFILE SCRIPT FOR REVIEWING PROFILES. 
@app.route("/user/<username>")
def user_profile(username):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT Username, UserEmail, UserPFP, UserJoinDate,
               UserReviewCount, UserTitle, UserDescription
        FROM AccountsDetail
        WHERE Username=?
    """, (username,))
    user = cursor.fetchone()

    if not user:
        return redirect("/browse")

    cursor.execute("""
        SELECT
            MovieList.FilmID,
            MovieList.FilmName,
            MovieList.FlimImageLink,
            CommentList.CommentRating,
            CommentList.CommentContents,
            CommentList.CommentTime
        FROM CommentList
        JOIN MovieList ON MovieList.FilmID = CommentList.MovieID
        WHERE CommentList.UserID = (
            SELECT UserID FROM AccountsDetail WHERE Username = ?
        )
        ORDER BY CommentTime DESC
    """, (username,))
    reviews = cursor.fetchall()

    conn.close()

    return render_template(
        "profile.html",
        username=user[0],
        email=user[1],
        pfp=user[2],
        joined=user[3],
        title=user[5],
        bio=user[6],
        reviews=reviews
    )

@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "user" not in session:
        return redirect("/login")

    conn = get_db()
    cursor = conn.cursor()

    # GET USER ID
    cursor.execute(
        "SELECT UserID FROM AccountsDetail WHERE Username=?",
        (session["user"],)
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        session.clear()
        return redirect("/")

    user_id = row[0]

    # FIND AND DELETE REVIEWS CORRESPONDING TO THIS USER
    cursor.execute("""
        SELECT DISTINCT MovieID
        FROM CommentList
        WHERE UserID=?
    """, (user_id,))
    affected_movies = cursor.fetchall()

    cursor.execute(
        "DELETE FROM CommentList WHERE UserID=?",
        (user_id,)
    )

    # RECALCULATE MOVIE RATINGS 
    for (movie_id,) in affected_movies:
        cursor.execute("""
            UPDATE MovieList
            SET FilmRating = (
                SELECT ROUND(AVG(CommentRating), 1)
                FROM CommentList
                WHERE MovieID = ?
            )
            WHERE FilmID = ?
        """, (movie_id, movie_id))

    # DELETE USER ACCOUNT. 
    cursor.execute(
        "DELETE FROM AccountsDetail WHERE UserID=?",
        (user_id,)
    )

    conn.commit()
    conn.close()

    # LOG OUT
    session.clear()
    return redirect("/")


#LOCAL FLASK - ACTIVATE BEFORE SUBMISSION
if __name__ == "__main__":
    app.run(debug=True)

#ngrok script - DO NOT RUN THIS ON MARKING - DEACTIVATE BEFORE SUBMISSION
#USED FOR COLLABORATION AMONG PEERS (HOSTING THE WEBSITE, FOR MULTIPLE PEOPLE TO ACCESS.)
#if __name__ == "__main__":
#    app.run(host="0.0.0.0", port=5000, debug=False)


