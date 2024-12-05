

# ShopMaster

A comprehensive shop management and billing system built with React and Node.js.

---

## Features

- 🏪 **Shop Management**
- 📝 **Bill Generation**
- 💰 **GST & Discount Calculations**
- 📊 **Reports & Analytics**
- 🔒 **Secure Authentication**
- 📱 **Responsive Design**

---

## Tech Stack

### Frontend
- React.js with Create React App
- Material-UI for components
- Redux Toolkit for state management
- Formik & Yup for form handling
- React PDF for invoice generation
- Jest & React Testing Library for testing

### Backend
- Node.js with Express
- Prisma ORM with MongoDB
- Passport.js for authentication
- Joi for validation
- Express Session for session management

---

## Getting Started

### Prerequisites
- **Node.js** (v14 or higher)
- **npm** or **yarn**
- **MongoDB** instance

### Installation

1. **Clone the repository:**
   ```bash
   git clone [your-repo-url]
   cd shopmaster
2. **Install dependencies:**
   ```bash
   npm install
   ```
3. **Set up environment variables:**
   Create a `.env` file based on `.env.example` and set the appropriate values.
4. **Start the development server:**
   ```bash
   npm start
   ```

## Available Scripts

- `npm run dev` - Starts both frontend and backend in development mode
- `npm run start:frontend` - Starts only the frontend
- `npm run start:backend` - Starts only the backend
- `npm test` - Runs the test suite
- `npm run build` - Creates production builds

## Testing

The project includes comprehensive test coverage using Jest and React Testing Library:
```bash
npm test
npm run test:coverage
```

## Project Structure

## Project Structure

```plaintext
shopmaster/
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── components/
│   │   ├── features/
│   │   ├── app/
│   │   └── ...
│   └── package.json
├── backend/
│   ├── src/
│   ├── prisma/
│   └── package.json
└── package.json
```


## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Create React App documentation
- Material-UI components
- Prisma documentation
- MongoDB Atlas
