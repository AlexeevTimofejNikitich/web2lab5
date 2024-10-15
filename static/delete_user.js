"use strict"

function fillModal(event) {
    let deleteUrl = event.relatedTarget.dataset.deleteUrl;

    let modalForm = event.target.querySelector("form");
    modalForm.action = deleteUrl;
}

window.onload = function () {
    let deleteModal = document.getElementById("delete-modal");
    deleteModal.addEventListener("show.bs.modal", fillModal);
}

document.addEventListener('DOMContentLoaded', (event) => {
            setTimeout(() => {
                let flashMessages = document.getElementById('flash-messages');
                if (flashMessages) {
                    flashMessages.style.transition = 'opacity 0.5s ease';
                    flashMessages.style.opacity = '0';
                    setTimeout(() => { flashMessages.remove(); }, 500);
                }
            }, 3000);
        });