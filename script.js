let userEmail = prompt("Please enter your email to start the voting process:");
if (!userEmail) {
    alert("Email is required to start the voting process!");
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


let currentSet = 0;
let userChoices = [];

function pickDog(name) {
    const timestamp = new Date().toISOString();
    const dog1 = dogs[currentSet * 2];
    const dog2 = dogs[currentSet * 2 + 1];

    const choice = {
        email: userEmail,
        timestamp: timestamp,
        imagesPresented: [dog1.name, dog2.name],
        userChoice: name
    };

    userChoices.push(choice);

    alert('You picked ' + name + '!');
    currentSet++;
    updateDogImages();
}

function updateDogImages() {
    if (currentSet * 2 >= dogs.length) {
        alert('You have seen all the dogs!');
        finishVoting();
        return;
    }

    const dog1 = dogs[currentSet * 2];
    const dog2 = dogs[currentSet * 2 + 1];

    document.getElementById('dog1-img').src = dog1.image;
    document.getElementById('dog1-desc').innerText = dog1.description;
    document.getElementById('dog1-btn').onclick = function () { pickDog(dog1.name); };

    document.getElementById('dog2-img').src = dog2.image;
    document.getElementById('dog2-desc').innerText = dog2.description;
    document.getElementById('dog2-btn').onclick = function () { pickDog(dog2.name); };
}

function finishVoting() {
    console.log("User Choices: ", userChoices);

    fetch('YOUR_SERVER_ENDPOINT', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(userChoices),
    })
    .then(response => response.json())
    .then(data => {
        console.log('Success:', data);
    })
    .catch((error) => {
        console.error('Error:', error);
    });
}


//function finishVoting() {
    //console.log("User Choices: ", userChoices);
    // You can also send the userChoices to a server for further processing
//}
