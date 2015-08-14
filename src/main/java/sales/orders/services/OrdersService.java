package sales.orders.services;

import sales.orders.domain.Order;
import sales.storage.domain.Storage;
import sales.users.domain.User;

import java.util.Date;
import java.util.List;

/**
 * Created by Volodya on 23.07.2015.
 */
public interface OrdersService {
    public Order get(long id);

    public List<Order> getAll();

    public Order save(Order order);

    public void delete(long id);

    public List<Order> getByStorages(List<Storage> storages);

    public List<Order> getByUserAndDate(User user, Date date);

    public List<Order> getByUserAndDateAfter(User user, Date date);
}
