package sales.orders.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import sales.orders.domain.Order;
import sales.storage.domain.Storage;
import sales.users.domain.User;

import java.util.Date;
import java.util.List;

/**
 * Created by Volodya on 23.07.2015.
 */
public interface OrderRepository extends JpaRepository<Order, Long> {

    public Order findById(long id);

    public void removeById(long id);

    public List<Order> StorageIn(List<Storage> storages);

    public List<Order> findByUserAndDate(User user, Date date);

    public List<Order> findByUserAndDateAfter(User user, Date date);
}
