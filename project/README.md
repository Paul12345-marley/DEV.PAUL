# Project Title: IYA PAUL KITCHEN (A Food Ordering Website for Lagos Residents)

### Video Demo:
https://youtu.be/SjxEewNmyOA?si=xaPfPjdarL_XEuJ5

### Description:
This project is a Food Portfolio Website that provides an intuitive and engaging platform for users in Lagos, Nigeria, to order home-cooked meals from IYA PAUL KITCHEN(IPK). The project is implemented using Python and Flask for backend functionality, along with HTML, CSS, and JavaScript for the frontend. The database is managed using SQLite. Below is a breakdown of each file and folder in the project:

#### Main Files and Directories
`app.py`
* This is the main entry point of the application.
* It handles routing, manages user sessions, and connects the frontend with the backend logic.
* Includes features like user authentication, ordering meals, and managing transactions.

`marley.py`
* Contains helper functions and decorators to streamline the application logic.
* It ensures modularity by separating reusable functions such as session checks and database queries.

`kitchen.db`
* This is the SQLite database that stores essential data for the application:
  * User information (e.g., usernames, emails, and passwords).
  * Meal details, including prices and descriptions.
  * Order history and transaction records.

`flask_session/`
* A directory used by Flask to store session-related data.
* Ensures that user sessions persist across different requests.

#### Frontend Templates (`templates/` Directory)
This folder contains all HTML files used to render the frontend. Each template corresponds to a specific webpage.

##### General Templates
`homepage.html`
* The landing page for the website, showcasing meal options and the restaurant's tagline.

`aboutus.html`
* Provides information about IYA PAUL KITCHEN, including its mission, vision, and team.

`PI.html` (Personal Information)
* Allows users to view and update their profile details, such as username and password.

##### Authentication Templates
`login.html`
* The login page where users enter their credentials to access their accounts.

`register.html`
* The registration page where new users sign up by providing their details.

`forget_password.html` and `reset_password.html`
* Handle password recovery for users who have forgotten their login credentials.

##### Order and Payment Templates
`menu.html`
* Displays the menu of meals available for ordering, along with prices.

`plate.html`
* A dynamic page for selecting meal quantities and customizing orders.

`payment.html`
* Guides users through the payment process, offering multiple payment options.

`success.html` and `success2.html`
* Display order confirmation and transaction success messages.

##### Miscellaneous Templates
`location.html`
* Shows the location of IYA PAUL KITCHEN on a map or provides directions for pickup orders.

`method.html`
* Allows users to choose delivery or pickup as their preferred order method.

`verify.html`
* Handles email or phone verification for user authentication.

`apology.html`
* A generic error page displayed when something goes wrong (e.g., invalid input or server error).

#### Static Assets (`static/` Directory)
This folder contains all static resources like images and CSS files used for styling and visuals.

##### Images
`logo.jpg`
* The official logo of IYA PAUL KITCHEN, displayed across the website for branding.

`Food Images (beans.jpg, fish.jpg, jollofrice.jpg, etc.)`
* Pictures of meals available on the menu, adding visual appeal to the site.

`face.jpeg`
* Likely used as a placeholder or profile picture for the user account section.

##### Stylesheets
`styles.css`
* The main CSS file for styling the website, including layout, colors, fonts, and responsive design.

`kitchen.css`
* Additional or specific CSS used for styling the kitchen or menu-related pages.

#### README.md
A markdown file that provides an overview of the project. Explains the project’s purpose, features, and instructions for setup and usage.
