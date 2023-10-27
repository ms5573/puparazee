document.getElementById("emailForm").addEventListener("submit", function(event) {
    event.preventDefault();
    startVoting();
    hideEmailForm();
});

let userEmail = "";
let currentDog = null; // To store the currently displayed dog that was selected

function startVoting() {
    userEmail = document.getElementById("userEmail").value;
    currentDog = null; // Reset
    displayTwoRandomDogs();
}

function hideEmailForm() {
    document.getElementById("emailDiv").style.display = "none";
}

const dogs = [
    { name: 'Max', image: 'images/dog1.png', description: 'Meet Max, a playful Golden Retriever who loves to fetch and play in the park.' },
    { name: 'Bella', image: 'images/dog2.png', description: 'Meet Bella, a charming Corgi who loves belly rubs and treats.' },
    { name: 'Oslav', image: 'images/dog3.png', description: 'Meet Oslav, a friendly Bulldog who loves to nap and play with his toys.' },
    { name: 'Tony', image: 'images/dog4.png', description: 'Meet Tony, a lively Poodle who loves to run and play with other dogs.' },
    // Additional dogs from the Excel file
    { name: 'Buddy', image: 'images/dog5.jpg', description: "This is just test data for now. Isn't this dog cute. He likes to play and go for walks" },
    { name: 'Molly', image: 'images/dog6.jpg', description: "This is just test data for now. Isn't this dog cute. He likes to play and go for walks" },
    { name: 'Sadie', image: 'images/dog7.jpg', description: "This is just test data for now. Isn't this dog cute. He likes to play and go for walks" },
    { name: 'Bailey', image: 'images/dog8.jpg', description: "This is just test data for now. Isn't this dog cute. He likes to play and go for walks" },
    { name: 'Lucy', image: 'images/dog9.jpg', description: "This is just test data for now. Isn't this dog cute. He likes to play and go for walks" },
    { name: 'Coco', image: 'images/dog10.jpg', description: "This is just test data for now. Isn't this dog cute. He likes to play and go for walks" }
];

function displayTwoRandomDogs() {
    const dogsContainer = document.getElementById("dogsContainer");
    dogsContainer.innerHTML = ""; // Clear previous dogs
    dogsContainer.style.display = "block";

    if (!currentDog) {
        currentDog = getRandomDog();
    }
    let secondDog = getRandomDog(currentDog);

    displayDog(currentDog, dogsContainer);
    displayDog(secondDog, dogsContainer);
}

function getRandomDog(excludeDog) {
    let availableDogs = dogs.filter(dog => !dog.shown && dog !== excludeDog);
    if (availableDogs.length === 0) {
        alert("All dogs have been shown!");
        startVoting(); // Reset the voting process
        return;
    }
    const randomIndex = Math.floor(Math.random() * availableDogs.length);
    const selectedDog = availableDogs[randomIndex];
    selectedDog.shown = true; // Mark as shown
    return selectedDog;
}

function displayDog(dog, container) {
    const dogDiv = document.createElement('div');
    dogDiv.innerHTML = `
        <img src="${dog.image}" alt="${dog.name}" width="200">
        <p>${dog.description}</p>
        <button onclick="voteForDog('${dog.name}')">Pick ${dog.name}</button>
    `;
    container.appendChild(dogDiv);
}

function voteForDog(dogName) {
    currentDog = dogs.find(dog => dog.name === dogName);
    displayTwoRandomDogs(); // Display the selected dog with a new dog
}