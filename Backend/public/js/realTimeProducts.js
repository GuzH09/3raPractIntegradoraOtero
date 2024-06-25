const socket = io();

const titleInput = document.querySelector("#title-input");
const descInput = document.querySelector("#desc-input");
const codeInput = document.querySelector("#code-input");
const priceInput = document.querySelector("#price-input");
const stockInput = document.querySelector("#stock-input");
const categInput = document.querySelector("#categ-input");
const productsView = document.querySelector("#products-view");

function send() {
    const product = {
        title: titleInput.value,
        description: descInput.value,
        code: codeInput.value,
        price: priceInput.value,
        stock: stockInput.value,
        category: categInput.value
    }
    socket.emit("addProduct", product);
    titleInput.value = "";
    descInput.value = "";
    codeInput.value = "";
    priceInput.value = "";
    stockInput.value = "";
    categInput.value = "";
}

function deleteProduct(productId) {
    socket.emit("deleteProduct", productId);
}

socket.on("refreshProducts", data => {
    let productsDiv = ""

    for (let item of data) {
        productsDiv += `
            <article>
                <h1>${item.title}</h1>
                <p>Precio: ${item.price}</p>
                <p>Stock: ${item.stock}</p>
                <p>Categoria: ${item.category}</p>
                <button id="id-${item._id}-button" class="delete-button" onclick="deleteProduct('${item._id}');">Eliminar</button>
            </article>
        `
    }

    productsView.innerHTML = productsDiv;
});

socket.on('statusError', data => {
    console.log(data);
    alert(data.error);
});