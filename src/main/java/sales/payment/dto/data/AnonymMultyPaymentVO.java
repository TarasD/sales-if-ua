package sales.payment.dto.data;

import sales.payment.creaditCard.domain.CreditCard;

import java.util.List;

/**
 * Created by volodya on 29.07.15.
 */
public class AnonymMultyPaymentVO {

    private List goodId;

    private String firstName;

    private String lastName;

    private String email;

    private CreditCard card;

    public List getGoodId() {
        return goodId;
    }

    public void setGoodId(List goodId) {
        this.goodId = goodId;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public CreditCard getCard() {
        return card;
    }

    public void setCard(CreditCard card) {
        this.card = card;
    }
}
