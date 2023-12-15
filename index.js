require('dotenv').config()
const express = require('express');
const passport = require('passport');
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate")
const basicAuth = require('express-basic-auth');
const app = express();
const ejs = require("ejs")
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const nodemailer = require('nodemailer');
const multer = require('multer');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const fs = require('fs')
const flash = require('express-flash');
const { functions } = require('lodash');

app.use(flash());

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static("public"))




let conn = mongoose.connect('mongodb://localhost:27017/SkinCareDB');
if (conn) {
  console.log('Connected')
}

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  googleId: String,
  carts: [
    {
      product_name: String,
      product_id: String,
      product_price: Number,
      product_img: String,
    }
  ],
  phoneNo: Number,
  billingDetails: {
    country: String,
    Full_Name: String,
    Address: String,
    City: String,
    State: String,
    Email: String,
    PhoneNo: Number,
  }
})
const adminSchema = new mongoose.Schema({
  name: String,
  password: String,
})

const productSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  price: {
    type: Number,
    required: true,
  },
  quantity: {
    type: Number,
    // You can add more specific validation or define a category schema
  },
  image: {
    data: {
      type: Buffer, // Store image data as a buffer
      required: true,
    },
    contentType: {
      type: String,
      required: true,
    },
    name: {
      type: String,
      required: true,
    },
  },

  // You can add more fields based on your requirements
});
// Multer setup
const storage = multer.memoryStorage(); // Store files in memory
const upload = multer({ storage: storage }); // Set file size limit

userSchema.plugin(passportLocalMongoose, { usernameUnique: false })
userSchema.plugin(findOrCreate)

// adminSchema.plugin(passportLocalMongoose)
// adminSchema.plugin(findOrCreate)
app.use(session({
  secret: 'secret wa niyen oo',
  resave: true,
  saveUninitialized: true,
  store: MongoStore.create({ mongoUrl: 'mongodb://localhost:27017/SkinCareDB' }), // Adjust the URL accordingly
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7, // 1 week
  },
}));

app.use(passport.initialize())
app.use(passport.session())
const ProductsModel = mongoose.model("ProductsModel", productSchema)
const UserModel = mongoose.model("UserModel", userSchema);
const AdminModel = mongoose.model("AdminModel", adminSchema);
passport.use(UserModel.createStrategy())

// passport.use(AdminModel.createStrategy())

// GOOGLE_CLIENT_ID = "408923561161-8484gr75vjcv72qallehvknndv6hbo8o.apps.googleusercontent.com"
// GOOGLE_CLIENT_SECRET = "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"
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3500/auth/google/callback"
},
  function (accessToken, refreshToken, profile, cb) {
    UserModel.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
const Product = mongoose.model("Product", productSchema);
passport.serializeUser(function (user, done) {
  done(null, user.id)
});
passport.deserializeUser(function (id, done) {
  UserModel.findById(id)
    .then(function (user) {
      done(null, user);
    })
    .catch(function (err) {
      done(err, null);
    });
});
app.use((req, res, next) => {
  res.locals.user = req.user; // This makes `user` available in your templates
  next();
});

const cartFunction = async (req, res, next) => {
  try {
    if (req.isAuthenticated()) {
      const userId = req.user._id;
      const user = await UserModel.findById(userId);

      if (!user) {
        console.log("User not found")
        res.locals.cartItems = []
      } else {
        const cartItems = user.carts || []
        const total = (price) => {
          cartItems.map(item => {
            price += item.product_price
          })
          return price
        }
      }
    } else {
      res.locals.cartItems = []
    }
    next()
  } catch (err) {
    console.error("Error retrieving cart items:" + err)
    res.locals.cartItems = []
    next()
  }
}
app.use(cartFunction)
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function (req, res) {
    // Successful authentication, redirect home.
    const username = req.user ? req.user.user.email : null;
    res.redirect('/my-account?username=' + encodeURIComponent(username));
  });



// Routes
app.get('/', async (req, res) => {
  try {
    const products = await Product.find({})
    res.render('index', { products: products });
  }
  catch (err) {
    console.log(err);
    res.render('error-404', { error: err });
  }

})



app.get('/login-register', (req, res, next) => {
  res.render('login-register', { user: req.user, message: req.flash('error') })
})

app.post('/login-register', (req, res, next) => {
  const { First_Name, PhoneNo, username, password } = req.body;

  console.log('Received registration request:', { First_Name, username });

  const newUser = new UserModel({ username, name: First_Name, phoneNo: PhoneNo });

  UserModel.register(newUser, password, (err, user) => {
    if (err) {
      console.error('Registration failed:', err);
      req.flash('error', 'Registration failed. Please try again.');
      return res.redirect('/login-register');
    }  // Authenticate the user after registration
    passport.authenticate('local')(req, res, () => {
      console.log('User authenticated and logged in successfully.');
      // Redirect to the desired page after successful authentication
      res.redirect('/cart');
    });
  });
});



app.get('/login', (req, res) => {
  res.render('login-register');
})
app.post('/login', (req, res) => {
  const user = new UserModel({
    username: req.body.username,
    password: req.body.password
  })
  req.login(user, (err) => {
    if (err) {
      console.log(err)
    } else {
      let username = req.user.username
      passport.authenticate("local")(req, res, () => {
        res.redirect('/my-account');
      })
    }
  })
})

// Middleware for regular users
const ensureAuthenticatedUser = (req, res, next) => {
  if (req.isAuthenticated() && req.user instanceof UserModel) {
    return next();
  }
  res.redirect('/login-register');
};
// Middleware to set user in the template context
app.use((req, res, next) => {
  res.locals.user = req.user; // This makes `user` available in your templates
  next();
});

// Your route handling



app.get('/my-account', session({ secret: 'secret wa niyen oo', resave: true, saveUninitialized: true }), ensureAuthenticatedUser, (req, res) => {
  // Check if there is a username passed in the query parameters
  const username = req.query.username || (req.isAuthenticated() ? req.user.username : null);
  res.render('my-account', { username: username });
});

app.post('/my-account', () => {

})




// Middleware for administrators
const adminAuth = basicAuth({
  users: { 'nina': '123444' }, // Replace with your actual admin credentials
  challenge: true,
  unauthorizedResponse: 'Unauthorized Access!'
});



app.get('/admin', session({
  secret: 'secret wa niyen oo', resave: true,
  saveUninitialized: true
}), adminAuth, (req, res) => {
  res.render('admin');
});



app.post("/admin", (req, res) => {

})

app.get('/product-add', adminAuth, (req, res) => {
  res.render('product-add')
})
app.post('/add-product', adminAuth, upload.single('productImage'), function (req, res, next) {
  const { product_name, desc, price, quantity } = req.body;

  const productImage = {
    data: req.file.buffer,
    contentType: req.file.mimetype,
    name: req.file.originalname
  };
  // Create a new product
  const newProduct = {
    name: product_name,
    description: desc,
    price: price,
    quantity: quantity,
    image: productImage,
  };

  const Product = mongoose.model("Product", productSchema);
  const product = new Product(newProduct)
  product.save()
    .then(() => {
      console.log("saved")
      res.redirect('/product-list')
    })
    .catch((err) => {
      console.log(err)
      res.status(500).send("Internal Server Error: " + err.message)
    })

});
// Middleware to set user and cart in the template context

app.get('/shop-fullwidth', async (req, res) => {
  try {
    const products = await Product.find({});
    res.render('shop-fullwidth', { products: products });
  } catch (err) {
    console.error(err);
    res.render('error', { error: err });
  }
});

app.post('/shop-fullwidth', (req, res) => {

})



app.get('/product/:productName', (req, res) => {
  const requestedProductName = req.params.productName
  console.log(requestedProductName)
  Product.findOne({ name: requestedProductName }).exec()
    .then(foundProduct => {
      if (!foundProduct) {
        res.render('error-404')
      } else {
        res.render("single-product", { product: foundProduct });
      }
    }).catch(err => {
      console.log(err);
      res.status(500).send("Internal Server Error");
    });
})
app.get('/product', async (req, res) => {
  try {
    const products = await Product.find({});
    res.render('shop-fullwidth', { products: products });
  } catch (err) {
    console.error(err);
    res.render('error-404', { error: err });
  }
})
app.post('/product', (req, res) => {
  const newCart = {
    product_name: req.body.productName,
    product_id: req.body.productId,
    product_price: req.body.productPrice,
    product_img: req.body.productImg,
  };


  const userId = req.user._id // Assuming you are using Passport and the user is authenticated
  console.log(userId)
  if (req.isAuthenticated()) {
    UserModel.findOneAndUpdate(
      { _id: userId },
      { $push: { carts: newCart } },
      { new: true } // This option returns the modified document instead of the original
    )
      .then((updatedUser) => {
        if (!updatedUser) {
          console.error("User not found");
          return res.status(404).send("User not found");
        }
        console.log("Cart added successfully");
        res.redirect('/cart');
      })
      .catch((err) => {
        console.error("Error adding cart:", err);
        res.status(500).send("Internal Server Error");
      });
  } else {
    res.redirect('/login-register')
  }
});

app.get('/cart', async (req, res) => {
  try {
    if (req.isAuthenticated()) {
      const userId = req.user._id;
      const user = await UserModel.findById(userId);

      if (!user) {
        console.log("User not found")
        return res.status(404).send("Please login or register")
      }
      const cartItems = user.carts || []
      const total = (price) => {
        cartItems.map(item => {
          price += item.product_price
        })
        return price
      }
      res.render("cart", { cartItems: cartItems, total: total })
    } else {
      res.render("cart2")
    }

  } catch (err) {
    console.error("Error retrieving cart items:" + err)
    res.status(500).send("Internal Server Error")
  }

})
app.post('/cart', (req, res) => {

});
app.post('/remove-cart', async (req, res) => {
  const userId = req.user._id;
  const productId = req.body.productId;

  try {
    const user = await UserModel.findById(userId);

    if (!user) {
      console.log("User not found");
      return res.status(404).send("Please login or register");
    }

    // Remove the item from the carts array
    console.log(productId)
    await user.updateOne({ $pull: { carts: { _id: productId } } });
    console.log("Deleted");
    res.redirect('/cart');
  } catch (err) {
    console.error(err);
    res.status(500).render('error-500', { error: err });
  }
});

app.get('/search', (req, res) => {
  res.render('search')
})
app.post('/search', (req, res) => {

}
);

app.get('/user-list', adminAuth, (req, res) => {
  UserModel.find()
    .then((users) => {

      res.render('user-list', { users })
    })
    .catch(err => {
      console.error(err);
      res.render('error', { error: err }); // Render an error page
    });


})
app.get('/user-profile', adminAuth, (req, res) => {
  res.render('user-profile');
})
app.get('/new-order', adminAuth, (req, res) => {
  res.render('new-order')
})
app.get('/order-history', adminAuth, (req, res) => {
  res.render('order-history')
})

app.get('/product-list', adminAuth, async (req, res) => {
  try {
    const products = await Product.find({});
    res.render('product-list', { products: products });
  } catch (err) {
    console.error(err);
    res.render('error-404', { error: err });
  }

})


app.post('/product-list', adminAuth, async (req, res) => {
  let productId = req.body.productId;
  console.log(productId)
  try {
    const product = await Product.findById(productId);
    product.deleteOne({ _id: productId }).exec()
    console.log("Deleted")
    res.redirect('/product-list')
  } catch (err) {
    console.log(err)
    res.render('error-404', { error: err })
  }

})

app.get('/edit-product/:productId', async (req, res) => {
  const productId = req.params.productId
  try {
    const productId = req.query.productId;

    // Find the product based on the productId in your MongoDB database
    const product = await Product.findById(productId);

    if (!product) {
      // If the product is not found, you can handle it accordingly (e.g., render an error page)
      return res.render('error-404', { error: 'Product not found' });
    }
    console.log(product)
    // Render the "update-product" page and pass the product details
    res.render('product-update', { product: product });
  } catch (error) {
    // Handle any errors that occur during the database query or rendering
    console.error(error);
    res.render('error-404', { error: 'Internal Server Error' });
  }
});

app.post('/edit-product', async (req, res) => {

  try {
    const { name, price, description, quantity } = req.body;
    const productId = req.body.productId;
    const updateProduct = {
      name: name,
      price: price,
      description: description,
      quantity: quantity,

    }
    console.log(updateProduct)
    // Find the product based on the productId in your MongoDB database
    const product = await Product.findByIdAndUpdate(productId, updateProduct, { new: true });

    if (!product) {
      // If the product is not found, you can handle it accordingly (e.g., render an error page)
      return res.render('error-404', { error: 'Product not found' });
    }
    console.log(product)
    // Render the "update-product" page and pass the product details
    res.render('product-update', { product: product });
  } catch (error) {
    // Handle any errors that occur during the database query or rendering
    console.error(error);
    res.render('error-404', { error: 'Internal Server Error' });
  }
})
app.get('/checkout', async (req, res) => {
  if (req.user.billingDetails === null) {
    try {
      if (req.isAuthenticated()) {
        const userId = req.user._id;
        const user = await UserModel.findById(userId);

        if (!user) {
          console.log("User not found")
          return res.status(404).send("Please login or register")
        }
        const user_details = {
          Full_Name: req.user.name,
          Email: req.user.username,
          PhoneNo: req.user.phoneNo,

        }
        const cartItems = user.carts || []
        const total = (price) => {
          cartItems.map(item => {
            price += item.product_price
          })
          return price
        }
        res.render("checkout", { cartItems: cartItems, total: total, user_details: user_details })
      } else {
        res.send("Login First")
      }

    } catch (err) {
      console.error("Error retrieving cart items:" + err)
      res.status(500).send("Internal Server Error")
    }
  }
  else {
    try {
      if (req.isAuthenticated()) {
        const userId = req.user._id;
        const user = await UserModel.findById(userId);

        if (!user) {
          console.log("User not found")
          return res.status(404).send("Please login or register")
        }
        const user_details = user.billingDetails
        const cartItems = user.carts || []
        const total = (price) => {
          cartItems.map(item => {
            price += item.product_price
          })
          return price
        }
        res.render("checkout", { cartItems: cartItems, total: total, user_details: user_details })
      } else {
        res.send("Login First")
      }

    } catch (err) {
      console.error("Error retrieving cart items:" + err)
      res.status(500).send("Internal Server Error")
    }
  }


})
app.post('/checkout', async (req, res) => {

  try {
    if (req.isAuthenticated()) {
      const userId = req.user._id;
      const user = await UserModel.findById(userId);
      const { country, full_name, address, city, state, email, phone_number } = req.body

      let billingDetails = {
        country: country,
        Full_Name: full_name,
        Address: address,
        City: city,
        State: address,
        Email: email,
        PhoneNo: phone_number,
      }
      user.billingDetails = billingDetails;

      // Save the updated user
      const cartItems = user.carts || []
      await user.save();

      res.render("checkout", { cartItems: cartItems, total: total, user_details: user_details })



    } else {
      res.send("Login First")
    }

  } catch (err) {
    console.error("Error retrieving cart items:" + err)
    res.status(500).send("Internal Server Error")
  }
})
app.get('/checkout-payment', async (req, res) => {
  res.redirect('/checkout')
})
app.post('/checkout-payment', async (req, res) => {
  // Process the form submission and send the email
  const userId = req.user._id;
  console.log(userId);
  try {
    if (req.isAuthenticated()) {
      const userId = req.user._id;
      const user = await UserModel.findById(userId);
      let country = user.billingDetails.country
      let Full_Name = user.billingDetails.Full_Name
      let Address = user.billingDetails.Address
      let city = user.billingDetails.City
      let State = user.billingDetails.State
      let Email = user.billingDetails.Email
      let Phone_Number = user.billingDetails.PhoneNo
      // Save the updated user

      const cartItems = user.carts || []
      const orderProducts = cartItems.map(item => item.product_name);
      const total = (price) => {
        cartItems.map(item => {
          price += item.product_price
        })
        return price
      }
    //   const orderDetails = `
    // Order Details:
    // - Products: ${orderProducts.join(', ')}
    // - Full Name: ${Full_Name}
    // - Email: ${Email}
    // - Address:${Address}
    // - Country:${country}
    // - City: ${city}
    // - State: ${State}
    // - Phone Number: ${Phone_Number}
    // `;
      // console.log(orderDetails)
      const templatePath = 'views/details-email.ejs';
      const templatePath2 = 'views/user-email.ejs';

// Read the HTML template file
const template = fs.readFileSync(templatePath, 'utf-8');
      const templateVariables={
        cartItems:cartItems,  
        Full_Name: Full_Name,
        Email: Email,
        Address: Address,
        country: country,
        city: city,
        State: State,
        Phone_Number: Phone_Number,
        total: total, // Include the function in template variables
      };
const template2 = fs.readFileSync(templatePath2, 'utf-8');
    
      const renderedTemplate = ejs.render(template, templateVariables);
      const renderedTemplate2 = ejs.render(template2, templateVariables);

          const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
          user: process.env.MAIL_USERNAME,
          pass:'bdkxhvlkvdqykjgq' ,
          clientId: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          refreshToken: process.env.OAUTH_REFRESH_TOKEN
        },
        tls: {
          rejectUnauthorized: false
        }
      });

      // Configure the email options
      const mailOptions2 = {
        from: 'joelayomide35@gmail.com',
        to: user.username,
        subject: 'Your Order',
        html:renderedTemplate2,
      };
      transporter.sendMail(mailOptions2, (error, info) => {
              if (error) {
                console.error("Error" + error);
      
              } else {
                console.log('Email sent sucessfully to user');
      
              }
            });
      const mailOptions = {
        from: 'joelayomide35@gmail.com',
        to: 'Nnenaonuma@gmail.com',
        subject: 'New Order',
        html:renderedTemplate,
      };
      transporter.sendMail(mailOptions, (error, info) => {
              if (error) {
                console.error("Error" + error);
      
              } else {
                console.log('Email sent sucessfully to admin');
      
              }
            });
    } else {
      res.send("Login First")
    }

  } catch (err) {
    console.error("Error " + err)
    res.status(500).send("Internal Server Error")
  }

})
app.get('/details-email', async (req, res) => {
  try {
    if (req.isAuthenticated()) {
      const userId = req.user._id;
      const user = await UserModel.findById(userId);

      const cartItems = user.carts || [];
      const total = calculateTotal(cartItems); // Replace with your actual total calculation function

      const orderProducts = cartItems.map(item => item.product_name);
      const orderDetails = `
        Order Details:
        - Products: ${orderProducts.join(', ')}
        - Full Name: ${user.billingDetails.Full_Name}
        - Email: ${user.billingDetails.Email}
        - Address: ${user.billingDetails.Address}
        - Country: ${user.billingDetails.country}
        - City: ${user.billingDetails.City}
        - State: ${user.billingDetails.State}
        - Phone Number: ${user.billingDetails.PhoneNo}
      `;

      res.render("details-email", { cartItems, total, orderDetails });
    } else {
      res.send("Login First");
    }
  } catch (err) {
    console.error("Error " + err);
    res.status(500).send("Internal Server Error");
  }
});

app.get('/about-us', (req, res) => {
  res.render('about-us')
})
app.post('/about-us', (req, res) => {

});
app.get('/blog', (req, res) => {
  res.render('blog-grid-basic')
})
app.post('/about-us', (req, res) => {

});

app.get('/service', (req, res) => {
  res.render('our-services')
})

app.post('/service', (req, res) => {

})

app.get('/contact', (req, res) => {
  res.render("contact-us")
})
app.post('/contact-us', (req, res) => {

})



app.get('/wishlist', (req, res) => {
  res.render('wishlist')
});

app.get('/coming-soon', (req, res) => {
  res.render("coming-soon")
})




app.get("*", (req, res) => {
  res.render('error-404')
})



app.listen(3500, () => {
  console.log("listening on Port 3500")
})