const contactForm = document.querySelector("[data-contact-form]");
const contactSuccess = document.querySelector("[data-contact-success]");
const contactError = document.querySelector("[data-contact-error]");

if (contactForm && contactSuccess && contactError) {
  contactForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (!contactForm.checkValidity()) {
      contactForm.reportValidity();
      return;
    }

    const submitButton = contactForm.querySelector("button[type='submit']");
    const originalButtonText = submitButton ? submitButton.textContent : "";

    contactError.hidden = true;

    if (submitButton) {
      submitButton.disabled = true;
      submitButton.textContent = "Sending...";
    }

    try {
      const response = await fetch(contactForm.action, {
        method: "POST",
        body: new FormData(contactForm),
        headers: { Accept: "application/json" }
      });

      if (!response.ok) throw new Error("Formspree submission failed");

      contactForm.hidden = true;
      contactSuccess.hidden = false;
      contactSuccess.focus();
    } catch (error) {
      contactError.hidden = false;
    } finally {
      if (submitButton) {
        submitButton.disabled = false;
        submitButton.textContent = originalButtonText;
      }
    }
  });
}
