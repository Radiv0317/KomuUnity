document.addEventListener('DOMContentLoaded', function() {
    const editProfileForm = document.getElementById('editProfileForm');
    const saveChangesBtn = document.getElementById('saveChangesBtn');
  
    editProfileForm.addEventListener('submit', function(event) {
      event.preventDefault();
  
      const formData = new FormData(this);
  
      fetch('/edit_profile', {
        method: 'POST',
        body: formData
      })
      .then(response => {
        if (!response.ok) {
          throw new Error('Failed to save changes');
        }
        return response.text();
      })
      .then(data => {
        alert(data); // Menampilkan pesan dari server
        // Redirect or perform any other action after successful save
      })
      .catch(error => {
        alert('Error: ' + error.message);
      });
    });
  });