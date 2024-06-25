import mongoose from 'mongoose'
import mongoosePaginate from 'mongoose-paginate-v2'

const productCollection = 'products'

const productSchema = mongoose.Schema({
  title: {
    type: String,
    require: true
  },
  description: {
    type: String,
    require: true
  },
  code: {
    type: String,
    require: true
  },
  price: {
    type: Number,
    require: true
  },
  status: {
    type: Boolean,
    require: false,
    default: true
  },
  stock: {
    type: Number,
    require: true
  },
  category: {
    type: String,
    require: true
  },
  thumbnails: {
    type: Array,
    require: false,
    default: []
  },
  owner: {
    type: String,
    require: false,
    default: 'admin'
  }
})

productSchema.plugin(mongoosePaginate)

const productModel = mongoose.model(productCollection, productSchema)

export default productModel
