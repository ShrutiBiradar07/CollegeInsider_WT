# # admin.py
# from flask import render_template, request, jsonify
# from flask_login import login_required
# from main import app  # Import your Flask app instance
# from pymongo import MongoClient
# from bson import ObjectId  # Import ObjectId from pymongo
# # MongoDB Configuration
# client = MongoClient('mongodb://localhost:27017/')
# db = client['college_reviews']
# collection = db['reviews']
# users_collection = db['users']

# @app.route('/admin', methods=['GET'])
# @login_required
# def admin_reviews():
#     # Retrieve all reviews, including those pending approval
#     reviews = list(collection.find({}, {'_id': 0}))

#     return render_template('admin_reviews.html', reviews=reviews)

# @app.route('/approve_review', methods=['POST'])
# @login_required
# def approve_review():
#     review_id = request.form.get('review_id')
    
#     # Update the review in the database to mark it as approved
#     collection.update_one({'_id': ObjectId(review_id)}, {'$set': {'approved': True}})

#     return jsonify(success=True)
