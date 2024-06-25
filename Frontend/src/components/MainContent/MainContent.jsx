import { Routes, Route } from 'react-router-dom'

import NavBar from './NavBar/NavBar'
import ItemListContainer from './ItemList/ItemListContainer'
import ItemDetailContainer from './ItemDetails/ItemDetailContainer'
import { CartProvider } from '../../context/CartContext'
import Cart from './Cart/Cart'
import Footer from './Footer/Footer'
import Profile from './Profile/Profile'
import ProtectedRoute from '../ProtectedRoute'
import Chat from './Chat/Chat'
import AdminManager from './AdminManager/AdminManager'
import { NotificationProvider } from '../../context/Notification'
import Checkout from './Checkout/Checkout'

function MainContent () {
  return (
        <>
            <NotificationProvider>
                <CartProvider>
                    <NavBar />
                    <Routes>
                        <Route element={<ProtectedRoute roleNeeded={['user', 'premium', 'admin']}/>}>
                            <Route path="/" element={<ItemListContainer />} />
                            <Route path="/category/:categoryId" element={<ItemListContainer />} />
                            <Route path="/item/:itemId" element={<ItemDetailContainer />} />
                            <Route path="/cart" element={<Cart />} />
                            <Route path="/profile" element={<Profile />} />
                            <Route path="/chat" element={<Chat />} />
                            <Route path="/checkout" element={<Checkout />} />
                        </Route>

                        <Route element={<ProtectedRoute roleNeeded={['admin', 'premium']} redirectTo="/" />}>
                            <Route path="/manager" element={<AdminManager />} />
                        </Route>
                    </Routes>
                </CartProvider>
            </NotificationProvider>
            <Footer />
        </>
  )
}

export default MainContent
