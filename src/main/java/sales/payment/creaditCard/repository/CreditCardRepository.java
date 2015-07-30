package sales.payment.creaditCard.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import sales.payment.creaditCard.domain.CreditCard;

/**
 * Created by volodya on 29.07.15.
 */
public interface CreditCardRepository extends JpaRepository<CreditCard, Integer> {
}
