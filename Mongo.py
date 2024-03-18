from pymongo import MongoClient

# Configure your MongoDB connection
client = MongoClient('mongodb://localhost:27017/')

# Create a new database named 'college_reviews'
db = client['college_reviews']

# Create a new collection named 'reviews' within the database
collection = db['reviews']

data = [
    {
        'college': 'Indian Institute of Technology Bombay (IIT Bombay)',
        'reviewer_name': 'Aditya Dhanwai',
        'review_text': "My journey at IIT Bombay has been nothing short of a dream come true. The campus is beautiful, and the academic environment is incredibly stimulating. The professors are highly knowledgeable and supportive. I've had opportunities to participate in exciting research projects and extracurricular activities. The infrastructure is top-notch, with well-equipped labs and libraries. Hostel life is fun, and there are numerous clubs and societies to join. Overall, IIT Bombay offers a world-class education and a vibrant campus life.",
    },
    {
        'college': 'Maharashtra Institute of Technology, Pune (MITAOE)',
        'reviewer_name': 'Rohit Patil',
        'review_text': "MITAOE is a great college that provides quality education. The faculty is experienced and dedicated to the students. The campus is spacious and well-maintained. The college offers a range of courses and encourages students to participate in extracurricular activities. The placement cell works diligently to secure job opportunities for the students. The library is well-stocked, and there are ample resources for research. MITAOE is an excellent choice for those looking for a well-rounded educational experience.",
    },
    {
        'college': 'Vishwakarma Institute of Technology, Pune (VIT Pune)',
        'reviewer_name': 'Shruti Biradar',
        'review_text': "My time at VIT Pune has been wonderful. The college has a serene campus with modern infrastructure. The faculty is approachable and supportive, always willing to help students. The college offers a variety of technical and cultural events, providing opportunities for students to showcase their talents. Hostel facilities are comfortable, and there are plenty of recreational spaces. The college also emphasizes industry-oriented learning, which is beneficial for future careers. VIT Pune is a great place to pursue engineering studies.",
    },
    {
        'college': 'National Institute of Technology Nagpur (NIT Nagpur)',
        'reviewer_name': 'Siddhesh Patil',
        'review_text': "NIT Nagpur has some of the best professors in the country. The faculty is highly qualified, and they encourage critical thinking and research. The campus is spacious, and there's a great focus on both academics and extracurricular activities. The library is extensive, and the laboratories are well-equipped. The college also maintains strong industry connections, which leads to excellent placement opportunities for students. NIT Nagpur provides a conducive environment for students to excel in their academic and personal development.",
    }
]


# Insert the sample data into the 'reviews' collection
collection.insert_many(data)

# Print a success message
print("Sample data inserted successfully into the 'reviews' collection.")
